# Host versus guest throughput: the guest was at the ceiling, the host falls short

2026-08-22, revised 2026-08-23 after the control run that reframed it. A Server 2022 guest running
on this laptop moved tunnel traffic about 1.5× faster than the laptop itself, on the same silicon,
with half the CPU. Two days of correlation followed. The measurement that finally located the
shortfall was a control that removed our code from the path entirely, and it should have been the
first thing run rather than the last.

## The control, and what it reframes

`ssh -L 5201:<iperf-server>:5201 <user>@<ssh-server>`, then `iperf3 -c 127.0.0.1 -R -t 60 -P 4` on
the same machine. OpenSSH does the forwarding; the VPN platform and our plug-in are not in the path.
Everything else — server, network, TCP connection count, channel multiplexing, crypto — is what the
tunnel uses.

| path (same laptop, same server, same day) | throughput | share of link |
|---|---|---|
| access link, downstream | ~620–650 Mbit/s | — |
| host, `ssh -L` control | **510** (steady ~500–530) | ~80% |
| guest, our tunnel | **493** | ~78% |
| host, our tunnel | **~326** (297 / 336 / 345) | ~51% |

Read the middle two rows together. The ~510 mark is what carrying bulk TCP over a single SSH
connection costs on this hardware — not link capacity, but the practical ceiling for this
architecture. **Our tunnel reaches 97% of it in the guest.** So there is no anomalously fast guest to
explain, which is what the first version of this document set out to do; there is a 36% shortfall on
the host, against the same binaries, the same server and the same switch.

That also retires an earlier data point: CLAUDE.md's `ssh -D` figure of 282 Mbit/s, from the era of
disproving the 8 Mbit ceiling, was measuring a single SOCKS stream on a different day and is not this
machine's capability. Do not use it as one.

## Setup

Quad-core i7-6700HQ, 8 logical CPUs. The guest is Server 2022 (build 20348.1) with **4 vCPUs
(2 cores) and 2.9 GB**, on the same host, attached to the same external virtual switch. Host is
Windows 11 build 26200. Same SSH server, same package binaries, same profile, MTU 1400 and
`maxFrameSize 65536` on both unless stated. Measurement is `iperf3 -R -t 60 -P 4`, so the tunnel
carries inbound traffic — the path with the receive-pool and doorbell machinery in it.

**The noise floor.** Three host tunnel runs in identical configuration measured 297, 336 and
345 Mbit/s: a **±8% spread**, so a single run on this machine cannot resolve a difference smaller
than roughly 15%. Several conclusions earlier in this project were drawn from single runs whose
differences were at or below that — including the MTU gain recorded in CLAUDE.md's throughput
section. The host/guest gap is 51% and the host/control gap is 36%, both far outside it.

## Where the shortfall is not: the plug-in host is idle

Context-switch tracing (`xperf -on PROC_THREAD+LOADER+CSWITCH+DISPATCHER -stackwalk
CSwitch+ReadyThread`, elevated) over a 61.6 s span covering the 345 Mbit/s run — the host at its
best, not a perturbed one:

| | |
|---|---|
| process CPU, whole span | **0.79 cores** of 8 |
| busiest thread (the stack thread) | 0.12 cores, 29,949 switch-ins |
| eight threadpool threads | 0.07–0.08 cores each |
| switch-outs: blocked / preempted | **69.9% / 25.6%** |
| switch-ins that had waited < 1 ms | **93.3%** (nonzero mean 6.7 ms, max 2.2 s) |

The wait reasons say what the threads are waiting on. The stack thread's dominant blocking reason is
`UserRequest` (13,048) — its own wait-for-work event — with `Ready`/`WrDispatchInt` preemptions
second (12,470, ~200/s). The threadpool threads sit on `WrQueue` (an I/O completion port, i.e. the
transport) and `WrAlertByThreadId`.

So at the host's best rate the plug-in host is **idle-waiting for bytes**, gets the CPU essentially
the moment it wants it, and saturates neither a thread nor a core. Internal serialisation would look
different: the stack thread blocking on locks with work queued behind it. It is not doing that.

Combined with the control, that brackets the shortfall tightly. Bytes can arrive at 510 Mbit/s. Our
stack is idle at 0.79 cores with sub-millisecond scheduling latency. The tunnel delivers 326. The gap
lies in the one stretch `ssh -L` does not traverse: **the platform reading the transport socket and
handing the bytes to `Decapsulate`** — the same delivery machinery
(`VpnChannelImpl::CompleteDelivery` → `DatagramSocketServer::CompleteDelivery`) that starved
activations during the watchdog hunt.

## The concurrency ceiling, and why it is no longer the explanation

From an earlier CPU-sampling trace of the plug-in host (1 kHz per CPU) bucketed into 10 ms windows,
6,002 active windows: mean **1.57 cores** per active window, 0.3% of windows reaching ≥ 2.5 cores,
one thread carrying ≥ 80% of process CPU in only 2.0%. That still stands as a description of the
host's concurrency shape — roughly three threads at ~0.5 core each, single-thread bursts real but not
dominant.

What it no longer supports is the conclusion drawn from it, that the guest simply gets ~1.6 cores of
uncontended time while a client OS with a desktop does not. The guest needs no such explanation: it
is at the architecture's ceiling. And the host is not starved for CPU — four physical cores idle, and
the context-switch data shows sub-millisecond waits.

The two figures also disagree and should not be quoted together: 1.57 cores per active window at
222 Mbit/s (profiled run, 32 KiB MTU) against 0.79 cores whole-span at 345 Mbit/s (unprofiled,
directly measured running time). Some of that is active-window versus whole-span averaging (~1.29
cores whole-span), some is the profiler's own overhead attributed to our threads, and the rest is
unexplained. The context-switch figure is the trustworthy one.

## Ruled out

Each cost real runs, so they are recorded to stop them being re-proposed.

- **The network, the SSH server, the crypto and the NIC.** The control saturates to 510 Mbit/s over
  the same path with the same server. This is the measurement that should have come first.
- **Our own stack, and CPU capacity.** Idle at 0.79 cores with 93% of scheduling waits under a
  millisecond, at the host's best rate — and the same binaries reach the ceiling in the guest.
- **Npcap** (a capture filter bound to the host's virtual-switch port, absent from the guest's path).
  Unbinding it measured 336 against 297 bound — then 345 with it bound again. No effect beyond noise.
  Verified host-only first: not bound to the physical NIC, and the switch's NDIS capture extension is
  `Enabled: True, Running: False`.
- **`NetworkThrottlingIndex`**, the client-only 10-packets-per-millisecond default. Refuted
  arithmetically: at MTU 1400 and 222 Mbit/s the host was already doing ~19.8 packets/ms, roughly
  double the cap, so it cannot have been in force. It is also an MMCSS mechanism that engages for
  multimedia playback, which was not running.
- **Power plan.** The host's plan governs physical clocks for the guest too, so the guest ran under
  the same constraint and still went faster. Changing it for a host run only would break the
  comparison, since the guest figures were taken under the existing plan.
- **NIC offloads and TCP settings.** Identical on both sides: CUBIC, initial congestion window 10,
  autotuning Normal, RSS and RSC enabled. The physical NIC is shared by both paths anyway.
- **A single pegged thread or CPU.** No CPU exceeds 76% busy in the sampled trace, all eight within
  64–76%, and no thread averages more than 0.26 of a core.
- **The MTU, between 1400 and 32768.** Differences on both machines are inside the noise floor, while
  **65535 is catastrophic**: 64 Mbit/s on the guest with 2,110 receive-buffer refusals, 188 Mbit/s on
  the host with 24,467. See CLAUDE.md's throughput section for the pool arithmetic; the guest sweep
  across 1400 / 8192 / 16384 / 32768 / 65535 is in `dumps\wsshvpn-vm-20348-mtu-sweep.log`.

## Still true, and still worth knowing

**The tunnel is strongly CPU-sensitive**: 326 → 108 Mbit/s, a 2.75× fall, purely from a compression
job competing for cores. That is much worse than proportional CPU sharing would predict, and it is
consistent with a latency-coupled path (delivery → drain → doorbell → acknowledgement) where lost CPU
share costs more than share. It is not, on the evidence above, the cause of the host/guest gap — an
idle host does not lose 36% to contention that is not there.

## Open

**The host's 36% shortfall against its own SSH ceiling is unexplained**, and the mechanism is now
localised to the platform's transport-delivery path rather than to anything of ours. Two hypotheses
remain:

1. **The platform's delivery path is slower on 26200 than on 20348.** Favoured: same binaries, same
   host, same switch, same server, and the shortfall is 36% against a ±8% noise floor.
2. **Host background activity interacting with the latency-coupled path.** Disfavoured: the threads
   wait for work, not for CPU, and four physical cores are idle.

They are confounded, because "Windows 11 26200" and "client OS carrying a desktop" are the same
variable in every measurement taken so far. **A Windows 11 guest on this same host and switch
separates them** — identical topology, identical contention profile, only the build differs. If it
reaches ~493, the platform-regression hypothesis dies and the host's own configuration is implicated;
if it drops to ~326, the regression is established well enough to report upstream. Until that run
exists, "26200 regressed the VPN stack" is a hypothesis, and it was asserted several times during
this investigation on evidence that did not support it.

Not worth doing next, recorded so it is not re-proposed: more tracing of our own process. It has
already answered its question — our code is not the constraint — and each pass over a `CSWITCH` trace
costs ten-plus minutes to tell us the same thing again.

## Method notes

Worth stating plainly, because ignoring them cost most of two days:

- **Measure the control before theorising.** One `ssh -L` run, five minutes, removed our code from
  the path and dissolved the question the previous version of this document was built around. The
  cost of not running it first was a CPU-sampling trace, a context-switch trace, an Npcap
  experiment, a registry hypothesis and two power-plan arguments.
- **Compare only equally idle runs.** The gap was first measured as 2× against a host run that was
  not idle. It is 1.5× against one that is.
- **Confirm the configuration on both sides.** Both arms must be at the same MTU; the plug-in logs
  `StartWithMainTransport accepted (mtu …, frame …)` on every connect, so there is no excuse for
  assuming it.
- **A before/after pair is not a result.** The Npcap hypothesis looked confirmed on one pair and died
  on the control run. With a ±8% noise floor, n=1 comparisons below ~15% mean nothing.
- **Beware cumulative counters.** The stack summary's `avg … B` for deliveries is cumulative over the
  session, not per-window; multiplying it by a per-window rate produced a figure three times the
  actual throughput, which is how that error was caught.
- **Know which run a trace covers.** The 61.6 s context-switch span was briefly attributed to a
  188 Mbit/s run and read as tracing overhead halving throughput; it covers the 345 Mbit/s run, and
  the caveat was imaginary. Match the span against the measurement before interpreting.
- **`typeperf` 1-second averages and whole-trace per-thread totals both hide burst structure.** The
  concurrency shape only became visible at 10 ms granularity.

Raw logs are in `dumps\` (gitignored): `wsshvpn-vm-20348-mtu-sweep.log`,
`wsshvpn-host-26200-clean-runs.log`, `cswitch-host.etl`.
