# Host versus guest throughput, and the noise floor that invalidated half of it

2026-08-22. A Server 2022 guest running on this laptop moved tunnel traffic about 1.5× faster than
the laptop itself, on the same silicon, with half the CPU. Chasing that produced one durable
measurement, one useful structural finding, a list of explanations that are now ruled out, and a
methodological lesson that matters more than any of them.

**Read the noise floor first.** Three host runs in identical configuration measured 297, 336 and
345 Mbit/s. That is a **±8% spread**, so on this machine a single run cannot resolve a difference
smaller than roughly 15%. Several conclusions earlier in this project were drawn from single runs
whose differences were at or below that — including the MTU gain recorded in CLAUDE.md's throughput
section, which deserves re-reading with this in mind.

## Setup

Quad-core i7-6700HQ, 8 logical CPUs. The guest is Server 2022 (build 20348.1) with **4 vCPUs
(2 cores) and 2.9 GB**, on the same host, attached to the same external virtual switch. Host is
Windows 11 build 26200. Same SSH server, same package binaries, same profile, MTU 1400 and
`maxFrameSize 65536` on both unless stated. Measurement is `iperf3 -R -t 60 -P 4`, so the tunnel is
carrying inbound traffic, which is the path with the receive-pool and doorbell machinery in it.

## What is measured

| | average | per-second spread | retransmits |
|---|---|---|---|
| host, idle, n=3 | **~326** Mbit/s (297 / 336 / 345) | 160–378, choppy | 642–1615 |
| host, while compressing a large file | **108** | 12–169 | 67 |
| guest, idle | **493** | 445–554, flat | 402 |

Three things stand out.

**The guest is ~1.5× the host** on identical hardware with half the CPU, and its per-second series is
far tighter. That gap is well outside the ±8% noise and is the one finding here that survived every
attempt to explain it away.

**The tunnel is strongly CPU-sensitive**: 326 → 108, a 2.75× fall, purely from a compression job
competing for cores. That is much worse than proportional CPU sharing would predict, and the
concurrency ceiling below is why.

**The MTU barely matters between 1400 and 32768** — differences on both machines are inside the noise
floor — while **65535 is catastrophic**: 64 Mbit/s on the guest with 2,110 receive-buffer refusals,
and 188 Mbit/s on the host with 24,467. See CLAUDE.md's throughput section for the pool arithmetic;
the sweep across 1400 / 8192 / 16384 / 32768 / 65535 on the guest is in
`dumps\wsshvpn-vm-20348-mtu-sweep.log`.

## The concurrency ceiling

From a CPU-sampling trace of the plug-in host (1 kHz per CPU), bucketed into 10 ms windows —
6,002 active windows:

| | |
|---|---|
| process CPU per window | **mean 1.57 cores** |
| windows reaching ≥ 2.5 cores | **0.3%** |
| windows with some thread ≥ 90% of a core | 7.1% |
| windows where one thread is ≥ 80% of all process CPU | 2.0% |

So the plug-in host **tops out around 1.5–2 cores of concurrency**, spread over roughly three threads
at ~0.5 core each. Single-thread bursts to a full core are real but not the dominant mode: one thread
carries the process only 2% of the time.

That ceiling reconciles two observations that otherwise conflict. Machine-wide CPU during a host run
averages 60–65%, which looks like headroom — but if the workload can never occupy more than ~1.6 of
4 physical cores, it cannot use that headroom, and a competing job takes slices of precisely the cores
it needs. Because the path is latency-coupled (delivery → drain → doorbell → acknowledgement), lost
CPU share costs more than proportionally, which is the 2.75× fall above.

It also explains the guest without needing a platform defect: a workload wanting ~1.6 cores of
*uncontended* time gets it on an otherwise-empty 4-vCPU guest, and competes for it on a client OS with
a desktop and background services.

Caveats: that trace was a profiled run at 32 KiB MTU (~222 Mbit/s), profiling perturbs, 10 ms buckets
on 1 kHz-per-CPU sampling are coarse to about ±10%, and samples cover only this process's threads —
kernel DPC and ISR work is not attributed to any thread, so real per-window cost is higher.

## Ruled out

Each of these cost real runs, so they are recorded to stop them being re-proposed.

- **Npcap** (a capture filter bound to the host's virtual-switch port, absent from the guest's path).
  Unbinding it measured 336 against 297 bound — then 345 with it bound again. No effect beyond noise.
  Verified it is genuinely host-only first: not bound to the physical NIC, and the switch's NDIS
  capture extension is `Enabled: True, Running: False`.
- **`NetworkThrottlingIndex`**, the client-only 10-packets-per-millisecond default. Refuted
  arithmetically: at MTU 1400 and 222 Mbit/s the host was already doing ~19.8 packets/ms, roughly
  double the cap, so it cannot have been in force. It is also an MMCSS mechanism that engages for
  multimedia playback, which was not running.
- **Power plan.** The host's plan governs physical clocks for the guest too, so the guest ran under
  the same constraint and still went faster. Changing it for a host run only would also break the
  comparison, since the guest figures were taken under the existing plan.
- **NIC offloads and TCP settings.** Identical on both sides: CUBIC, initial congestion window 10,
  autotuning Normal, RSS and RSC enabled. The physical NIC is shared by both paths anyway.
- **CPU capacity.** The box delivers 493 Mbit/s through the guest at 60% total CPU and 326 on the
  host at 65%, so the host was not limited by machine capacity. The concurrency ceiling, not
  saturation, is the constraint.
- **A single pegged thread or CPU.** No CPU exceeds 76% busy in the trace, all eight are within
  64–76%, and no thread averages more than 0.26 of a core over the run.

## Open

**The ~1.5× host/guest gap is unexplained.** Remaining candidates, in the order I would test them:

1. **Background activity on a client OS versus a bare server install.** Given that background noise
   alone moves this host ±8% run-to-run, a systematic version of the same effect is plausible.
2. **The remaining host-path asymmetry**: a bridge filter on the host's switch port that the guest
   does not have.
3. **The OS build itself.** A Windows 11 guest on this same host and switch would isolate this
   cleanly — same topology, only the OS differs. Until that exists, "26200 regressed" is a
   hypothesis, not a finding, and it was asserted several times during this investigation on evidence
   that did not support it.

**The measurement that would actually discriminate** is context-switch tracing rather than sampling:
`xperf -on PROC_THREAD+LOADER+CSWITCH+DISPATCHER` for 30 seconds on an unprofiled run gives ready
time and wait reason per thread, which distinguishes threads waiting on each other (our
serialisation) from threads waiting on the platform (delivery cadence). Everything above is
correlation; that would be causation.

## Method notes

Worth stating plainly, because ignoring them cost most of a day:

- **Compare only equally idle runs.** The gap was first measured as 2× against a host run that was
  not idle. It is 1.5× against one that is.
- **Confirm the configuration on both sides.** Both arms must be at the same MTU; the plug-in logs
  `StartWithMainTransport accepted (mtu …, frame …)` on every connect, so there is no excuse for
  assuming it.
- **A before/after pair is not a result.** The Npcap hypothesis looked confirmed on one pair and died
  on the control run. With a ±8% noise floor, n=1 comparisons below ~15% mean nothing.
- **Beware cumulative counters.** The stack summary's `avg … B` for deliveries is cumulative over the
  session, not per-window; multiplying it by a per-window rate produced a figure three times the
  actual throughput, which is how the error was caught.
- **`typeperf` 1-second averages and whole-trace per-thread totals both hide burst structure.** The
  concurrency ceiling only became visible at 10 ms granularity.

Raw logs are in `dumps\` (gitignored): `wsshvpn-vm-20348-mtu-sweep.log`,
`wsshvpn-host-26200-clean-runs.log`.
