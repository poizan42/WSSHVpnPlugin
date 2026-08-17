# Future experiment: run SSH over the platform-owned transport

Status: **not started** — design sketch and open questions, written down before the context that
produced it evaporates. Nothing here is committed to; the current loopback-dummy architecture works
(165 Mbit/s peak, clean lifecycle) and stays until every unknown below is answered cheaply.

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

1. **Does the plug-in-initiated send path actually transmit?** `AppendVpnSendPacketBuffer` +
   `FlushVpnSendPacketBuffers` are the documented way to send outside any callback, but their
   receive-side twins (`AppendVpnReceivePacketBuffer` + `FlushVpnReceivePacketBuffers` from a
   worker thread) **return success and silently deliver nothing** — the M0′(5) result. Until the
   send side is proven different, the whole design is speculative. Cheapest probe: during an
   established session on the *current* architecture, associate nothing new — just fill a send
   buffer with bytes the SSH server will ignore, flush, and watch a packet capture on the physical
   NIC for whether it hits the wire of the (dummy) transport at all; then repeat with the real
   socket associated. Also probe: does it work before `Start`? (The SSH handshake must transmit
   before any `Encapsulate` ever fires. If not: `Start` first — the addresses are static, from the
   profile — then handshake through the started channel.)
2. **Ordering under concurrency**: SSH.NET serializes its writes, but confirm the platform
   preserves append order across flushes from different threads, and across the boundary with
   whatever the keep-alive path sends.
3. **The delivery prolog at line rate**: `VpnChannelImpl::CompleteDelivery` — the machinery that
   starved activations when the doorbell flooded it — would now process every inbound chunk of a
   150+ Mbit/s stream. Shipping SSL-VPN plug-ins live on this path, so it is presumably engineered
   for real traffic, but our only data point is that it *can* starve activations. Measure
   activation completion latency during a full-speed download before trusting it.
4. **Throughput parity**: the pipe adds one copy inbound (encapBuffer → pipe) and the chunked
   append path outbound. Raw ABI from day one (`VpnChannelAbi` gains the send-pool slots, header
   citations mandatory — this API family has two inverted slot orderings already documented) or
   the RCW-per-packet ceiling returns.

## What survives even if everything works

- **A doorbell, probably.** Timer-driven *inbound* injections still need a `Decapsulate` visit
  with no inbound SSH data to provoke one — the clean case is the stack retransmitting a segment
  to the client precisely because no ACK arrived: server idle, client silent, packet waiting,
  no visit. Either accept that such packets wait for the next real inbound byte, or keep a
  loopback `DatagramSocket` as the **second** transport (the API allows TCP + UDP;
  `VpnPacketBuffer.TransportAffinity` steers buffers between them) purely as a doorbell.
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
