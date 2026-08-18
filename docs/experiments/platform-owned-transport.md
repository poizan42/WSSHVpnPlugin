# Future experiment: run SSH over the platform-owned transport

Status: **probes 1–3 answered (2026-08-17/18): the send path works after `Start` (deadlocks
before it) and preserves order under concurrency, but sustained datagram deliveries starve
activations from ~5,000/s (~56 Mbit/s) and ceiling at ~8,500/s — a datagram outer transport is
not viable at line rate, so the design now hinges on the TCP stream transport's delivery
granularity, which only a real attempt (or a `StreamSocketListener` experiment) can answer.**
Nothing here is committed to; the current loopback-dummy architecture works (165 Mbit/s peak,
clean lifecycle) and stays.

## The idea

Today the platform gets a loopback dummy transport it pumps for nothing, and SSH runs on a socket
of its own, source-bound to the physical interface. The alternative: associate the **real SSH TCP
socket** as the outer transport and let the platform own it entirely. SSH.NET never touches a
socket again — the fork's `SshTransport` seam gets a pipe-backed implementation instead:

- **Inbound**: `Decapsulate(encapBuffer)` copies the received wire bytes into a `PipeWriter`;
  the transport's `Read` drains the `PipeReader`. SSH is a self-framing byte-stream protocol, so
  arbitrary chunk boundaries are exactly what SSH.NET's parser already expects. This half is
  mechanically proven: the banner experiment delivered the SSH server's 42-byte identification
  string to `Decapsulate` verbatim, before `Start` had even completed.
- **Outbound**: the transport's `Write` requests buffers from the send pool
  (`RequestVpnPacketBuffer(VpnDataPathType.Send, …)`), chunks the bytes at `maxFrameSize`
  (~22 buffers for a full 32 KB SSH packet), `AppendVpnSendPacketBuffer`s each and
  `FlushVpnSendPacketBuffers` once per write. **Every** wire byte goes this way —
  `encapsulatedPackets` and `controlPacketsToSend` stay permanently empty, because SSH is a
  strictly ordered byte stream and a single send lane is the only path whose global ordering is
  under our control; nothing documents the transmit order across the three send vehicles, and one
  reordered byte is a failed MAC.
- `Encapsulate` keeps exactly its current job — rotate the list, hand the L3 packets to the stack —
  and `Decapsulate` becomes pipe-write plus the usual bounded drain of ready IP packets.

Mental model that makes this coherent (and matches how the current code already treats it):
`Decapsulate` is not "process this buffer", it is *a visit from the platform* — the `encapBuffer`
is merely what provoked the visit, and the out-list carries whatever is ready regardless of where
it came from. Visits must be provoked, and each visit must bound its own work (the 512-append cap
and the 90-second activation watchdog both still apply).

## Why bother

1. **The source-binding wart disappears.** The platform pins its own transport's flow to the
   physical interface — that is the design intent of `AssociateTransport` — so `OutboundInterface`,
   the `<NetworkAdapter>` profile requirement, and the nesting caveat should all evaporate.
   (Verify, don't assume.)
2. **True push wake**: inbound SSH data raises `Decapsulate` via the ControlChannelTrigger
   directly, which today's doorbell only simulates.
3. `LoopbackTransport` and most of its choreography go away; the platform's RIO pump does the
   socket I/O.

## What it stands or falls on — probe in this order

1. **Does the plug-in-initiated send path actually transmit? ANSWERED YES — 2026-08-17.**
   `AppendVpnSendPacketBuffer` + `FlushVpnSendPacketBuffers` transmit, immediately. Probed on the
   live loopback build, which makes the verdict binary: the platform's side of the main transport
   is cross-connected to our own back socket, so anything it transmits arrives there and nothing
   else can. Three rounds from a timer worker thread outside any callback, alternating
   `RequestVpnPacketBuffer(VpnDataPathType.Send, …)` and `GetVpnSendPacketBuffer`: every payload
   arrived on the back socket **in the same millisecond as the flush**. The asymmetry with the
   receive side is therefore real and proven in both directions on healthy channels: the
   receive-side twins (`AppendVpnReceivePacketBuffer` + `FlushVpnReceivePacketBuffers` from a
   worker) return success and silently deliver nothing — the M0′(5) result, whose provenance was
   challenged once (could it have been a pre-IPv6 session whose `Start` had failed?) and then
   settled from the preserved session logs: every probe run was on a healthy started channel, and
   on the loopback builds (2026-08-15/16) the doorbell path's ICMP echo landed milliseconds before
   each silent worker append. The pre-`Start` half is also answered — **NO, and worse than a
   refusal (2026-08-17)**: `RequestVpnPacketBuffer(VpnDataPathType.Send, …)` called after
   `AssociateTransport` but before `Start*` **blocks indefinitely** — no return, no exception —
   presumably waiting on buffer pools that only `VpnExeChannelCreate` (inside `Start*`) creates.
   The blocked connect activation was cancelled by the platform (`Terminating`) ~5 s in, the host
   killed, and the platform's automatic connect retries hit the same wedge in a **fresh host each
   time** (a once-per-process latch contains nothing) until `ConnectProfileAsync` failed with
   `ServerConnection` after three attempts. Two consequences: the design's connect ordering is
   fixed as associate → `Start` (the addresses are static, from the profile) → SSH handshake
   through the started channel; and probe hygiene — any probe touching the channel pre-`Start`
   must run on a worker with a bounded wait, because an inline block burns the entire connect,
   platform retries included.
2. **Ordering under concurrency — ANSWERED, order holds (2026-08-18).** Probed with numbered
   payloads counted at the back socket, ~2500 datagrams in three phases: 50 flushes of 20 appends
   each (the 32 KB-SSH-packet-chunked-at-maxFrameSize shape) arrived 1000/1000 with zero reorders
   and zero gaps; sequential append+flush turns taken by four threads under a lock — SSH.NET's
   serialized-writes-hopping-threads pattern, the load-bearing case — arrived 500/500 in exact
   global order; and four *uncoordinated* concurrently-flushing threads kept all four substreams
   complete and monotonic with no exceptions, so the API is thread-safe with margin. Throughput
   during the probe: ~1000 append+flush cycles in ~90 ms on a live tunnel. (The keep-alive
   boundary is untestable and moot: `GetKeepAlivePayload` is never called, and the design sends
   SSH's own keepalives through the same single lane as everything else.)
3. **The delivery prolog at line rate — ANSWERED for datagrams, and it is the design's boundary
   (2026-08-18).** Probed by blasting 1400-byte datagrams from the back socket into the platform's
   front socket in stepped phases while watching activation completions (their log budget
   temporarily raised): at **1,000/s** (~11 Mbit/s) `Decapsulate` keeps pace exactly but the
   rolling scheduling activation stretched from its 2–8 s baseline to **26 s**; at **5,000/s**
   (~56 Mbit/s) delivery saturates near 4,000/s and the in-flight activation **could not complete
   at all while the blast lasted** — it completed five milliseconds after the pressure stopped,
   the prolog-starvation mechanism caught in the act; **unpaced** (~30,000/s offered) the pump
   ceilings at **~8,500 visits/s** (~100 Mbit/s of 1400-byte deliveries) with the excess dropped
   at the socket buffer. No kills — 45 s of blast stays under the 90-second execution by design.
   Consequence: **a datagram outer transport is not viable at sustained line rate** — anything
   above ~56 Mbit/s sustained for 90 s gets the host killed, and ~100 Mbit/s is the delivery
   ceiling regardless. The cost is per-delivery, not per-byte, so the design now hinges on the
   **TCP stream transport's delivery granularity** — 64 KB chunks would mean ~200 deliveries/s at
   100 Mbit/s, trivially survivable — which the loopback dummy cannot probe (TCP cannot
   cross-connect without a `StreamSocketListener`, the one app-container loopback shape with
   doubted behaviour). That question is only answerable with a real TCP transport — i.e. by the
   first end-to-end attempt, or a listener experiment first.
4. **Throughput parity**: the pipe adds one copy inbound (encapBuffer → pipe) and the chunked
   append path outbound. Raw ABI from day one (`VpnChannelAbi` gains the send-pool slots, header
   citations mandatory — this API family has two inverted slot orderings already documented) or
   the RCW-per-packet ceiling returns. **This includes the `IVpnPlugIn` boundary itself**: every
   `Decapsulate` dispatch through the CsWinRT-authored CCW materializes projected wrappers for its
   four parameters, and probe 3's session measured the cost directly — 38 gen0 collections across
   ~203k visits versus ~zero when idle, i.e. a subset of the parameters (most plausibly the two
   lists) allocates a fresh RCW per call while the channel and the pool-recycled `encapBuffer`
   ride CsWinRT's identity cache. Per-batch today that is noise; at delivery granularity it is
   packet-path allocation, so the design requires the authoring twin of `VpnChannelAbi`: a
   hand-rolled CCW whose `IVpnPlugIn` vtable is `[UnmanagedCallersOnly]` stubs receiving the raw
   interface pointers, handed to `ProcessEventAsync` through its own raw ABI slot — which also
   dissolves the per-batch QI-back dance (`GetList` re-deriving the raw pointer from the wrapper).

## What survives even if everything works

- **A doorbell, probably.** Timer-driven *inbound* injections still need a `Decapsulate` visit
  with no inbound SSH data to provoke one — the clean case is the stack retransmitting a segment
  to the client precisely because no ACK arrived: server idle, client silent, packet waiting,
  no visit. Worker-thread injection is not an out: it returns success and delivers nothing, and
  that held on healthy channels (see probe 1). Either accept that such packets wait for the next
  real inbound byte, or keep a loopback `DatagramSocket` as the **second** transport (the API
  allows TCP + UDP; `VpnPacketBuffer.TransportAffinity` steers buffers between them) purely as a
  doorbell.
- The transition-ring discipline, the per-visit append bound, and the buffer-rotation invariant
  in `Encapsulate` — all of it is about the watchdog and buffer ownership, not about which socket
  the platform owns.

## Documentation honesty note

The `Decapsulate` docs ("a buffer … containing any number of IP packets") describe the
datagram-transport case, where protocol designs make one datagram carry whole messages. On a
`StreamSocket` the buffer boundary is just whatever the read returned — the banner arrived as
exactly 42 bytes because the link was idle, not because the platform framed it. This family's
documentation is demonstrably sloppy (the `Encapsulate` parameter is misspelled
`encapulatedPackets` in the API metadata; `SetErrorMessage` and `RequestCustomPrompt` ship as
"Not supported"), so treat it as describing the common vendor case, not a contract.
