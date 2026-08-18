# Where the tunnel's throughput ceiling actually is (2026-08-18)

The first honest measurement of the tunnel's capacity, and the attribution of its ceiling. Prior
numbers — the loopback-dummy architecture's 165 Mbit/s peak included — all had a third-party
download server as an uncontrolled variable; this session measured against a source we control
and profiled the host while it ran. Architecture at the time of measurement: the platform-owned
transport (see `docs/experiments/platform-owned-transport.md`), immediately before its merge to
master.

## Method

Worth recording because two parts of it are traps:

1. **The source**: `iperf3 -s` on the SSH server, but targeted at a loopback alias
   (`sudo ip addr add 198.51.100.1/32 dev lo` — TEST-NET-2, unroutable, no conflict) rather than
   the server's real address. This matters because **the platform's transport pinning is a host
   route**: `Get-NetRoute` shows a `/32` for the SSH server's address out the physical NIC, so any
   traffic addressed to the server itself bypasses the tunnel entirely. The first measurement made
   exactly that mistake and cleanly measured the raw line instead (a useful calibration, see
   below). Targeting the alias sends the flow through the tunnel's half-default routes, across our
   stack and one `direct-tcpip` channel, to the server's own loopback — one traversal of exactly
   our path.
2. **The profiler**: per-thread CPU deltas via `ProcessThread.TotalProcessorTime`, sampled from
   PowerShell each second (no suspension, safe during load), plus a single `cdbX64 -pv` all-thread
   stack snapshot mid-run with **offline symbols only** — a symbol fetch through a loaded tunnel
   is self-sabotage, and thread identity comes from `SetThreadDescription` names visible in the
   snapshot ("wsshvpn-stack", ".NET Long Running Task").

## Numbers

| Path | Down (1 stream) | Down (4 streams) | Up |
|---|---|---|---|
| Raw line (via the pinning bypass) | ~500–630 Mbit/s | — | ~110 Mbit/s |
| Through the tunnel | **136 Mbit/s** | **151–158 Mbit/s** | **38.8 Mbit/s** |

The line is nominally 1000/100; the raw measurements are its realistic ceiling, and the upload
figure is the line's cap, not the tunnel's.

## Attribution

During the 136 Mbit/s single-stream run, on 8 logical cores:

- **`wsshvpn-stack` (T-Stack): ~74% of one core.** The snapshot caught it inside
  `ChannelDirectTcpip.Dispose → WaitHandle.Dispose → CloseHandle` — channel-teardown churn on top
  of its steady-state work (packet building, checksums, copies into platform buffers). One
  snapshot is not a distribution; the dispose frame says teardown cost is real, not that it
  dominates.
- **The SSH `MessageListener` thread: ~50% of one core.** Caught inside
  `Session.ReceiveMessage → HMACSHA256.TransformBlock → HashProviderCng.AppendHashData →
  BCryptHashData`. That frame is a finding in itself: **the negotiated cipher suite is
  CTR/CBC + HMAC, not AES-GCM**, so every SSH packet pays a separate MAC pass through per-call
  BCrypt P/Invokes on the single receive thread.
- **The platform's delivery path: exonerated.** Stream deliveries ran at roughly 400–500/s of
  ~40 KB chunks — about 5% of the ~8,500/s serialized-delivery ceiling measured in probe 3b —
  with gen0 at single digits per 30 s after the hand-rolled CCW. Nothing platform-side is close
  to the limit.

The same two threads exist unchanged in both the loopback-dummy and platform-owned architectures,
which is why both landed in the same 130–165 Mbit/s band against download servers: the transport
architecture never was the bottleneck at these rates.

## What this points at next

1. **Cipher negotiation**: find out what suite the session actually negotiates and why AES-GCM
   (single pass, hardware, no separate MAC) loses — the listener's HMAC pass would disappear
   outright. Log the negotiated algorithms at connect as the first step.
2. **The upload path** (38.8 Mbit/s vs the line's ~110): never profiled at rate; the send path
   encrypts on the caller's thread and outbound channel windowing has never been examined under
   sustained upload.
3. **T-Stack**: a real sampled profile (not one snapshot) to split steady-state packetization from
   channel-teardown churn; the iperf parallel runs open and close channels far less than a browser
   does, so the 74% under a single long-lived flow is mostly steady-state cost.

## Caveats

- Thread attribution rests on per-second CPU deltas (robust) plus a single stack snapshot per
  thread (an existence proof of the named code paths, not a profile). The BCrypt/HMAC frame and
  the dispose frame are real; their relative shares within each thread's total are not measured.
- The raw-line figures vary with the ISP's day; the tunnel figures were taken minutes apart on the
  same line and are internally comparable.
- Both endpoints of the measurement live on machines we control; the server-side loopback hop is
  effectively free and does not shape the result.
