# Is Windows CNG leaving crypto performance on the table? (2026-08-20)

**Question.** The MAC pass measured 12% of the plug-in host's CPU (see
`2026-08-19-release-build.md`). Microsoft's CNG is not always the best-optimized implementation, so
would shipping OpenSSL in the package buy anything?

**Answer: no, not enough to be worth it.** OpenSSL leads by ~1.1–1.2× at 32 KB blocks and ~1.3–1.5×
at the MTU-sized blocks the tunnel actually produces. Shipping and patch-tracking libcrypto for that
is a bad trade for a security-critical dependency. The real win is not the library, it is **not
needing the MAC at all** — and that one is now measured in production rather than projected: moving
to AES-GCM took crypto from **12.7% of the plug-in host's CPU to 1.7%**, and 3.7× cheaper per byte.

**Read the dated section at the end before quoting anything above it.** The block size this document
first reasoned about was wrong, which moved both the OpenSSL ratio and the AEAD gain.

## Method

The clean comparison is available because `System.Security.Cryptography` uses **CNG on Windows and
OpenSSL on Linux**. So the same managed benchmark, on the same CPU, isolates the backend and nothing
else — no harness difference, no interop difference, no different measurement loop.

- Windows: .NET 10.0.11, CNG (`bcryptprimitives.dll`).
- WSL2 Ubuntu on the same machine: .NET 10.0.111, OpenSSL 3.5.5.
- i7-6700HQ (Skylake, 4 cores / 8 threads): AES-NI and PCLMULQDQ, **no SHA extensions**.
- 32 KB blocks — the size the observed profile is closest to, since a bulk download has the server
  sending near-maximum SSH packets. 1 s per case, 100 warm-up iterations, six rounds **interleaved**
  Windows/WSL so both arms see the same thermal and load conditions.

Two caveats on the method itself. WSL2 is a VM, so its arm carries whatever overhead that adds; for
a pure-compute test that should be negligible but it is not zero. And this is a laptop: run-to-run
spread is roughly ±20%, the same order as the difference being measured, so treat the ratios as
"about parity" rather than as precise figures.

## Numbers

Six interleaved rounds, 32 KB blocks, MiB/s, median with range:

| | CNG (Windows) | OpenSSL (WSL) | ratio |
|---|---|---|---|
| SHA-256 | 230 (197–265) | 264 (167–285) | 1.15× |
| HMAC-SHA256, persistent instance | 240 (168–265) | 293 (268–301) | 1.22× |
| AES-256-GCM encrypt+tag | 2161 (1528–2388) | 2348 (1994–2404) | 1.09× |

A seventh Windows run, taken later on a fully idle machine, measured CNG at **262 / 270 / 2445** —
at or above the OpenSSL medians for all three. That is one unpaired sample rather than another
round, but it points the same way: on this CPU the two backends are close enough that ordinary
machine noise swamps the difference.

The number that actually matters is in the same table, and it is not a comparison between backends:
**AES-GCM is ~9× faster per byte than HMAC-SHA256** (2161 against 240 on CNG; 2348 against 293 on
OpenSSL). GCM's GHASH is hardware here via PCLMULQDQ while SHA-256 is software, because Skylake has
no SHA extensions.

Projected onto the measured download profile (756 MiB moved in a 37.3 s window, 37.44 s of process
CPU):

| suite | crypto CPU | share of process |
|---|---|---|
| AES-CTR + HMAC-SHA256, CNG (what was measured) | 5.45 s | 14.6% |
| AES-GCM, CNG | ~0.8 s | ~2% |
| AES-GCM, OpenSSL | ~0.7 s | ~2% |
| AES-CTR + HMAC, OpenSSL | ~4.5 s | ~12% |

So the AEAD cipher order is worth ~12 points of process CPU; the crypto library is worth ~1–2 points
in the non-AEAD case and nothing much in the AEAD case.

## The mistake that nearly went into this document

The first run of this benchmark reported CNG at 122 MiB/s for SHA-256 and 908 for AES-GCM, against
OpenSSL's 262 and 2003 — a 2–3× gap, and a conclusion that CNG was badly behind. **A package MSBuild
was still finishing in the background at the time.** Repeats on an idle machine put CNG at 230 and
2161, and the gap collapsed to ~1.1×.

Two things to take from that. Never benchmark next to a build — obvious, and it still happened here
because the build had been started in the background and its completion notice had not arrived yet.
And a single measurement that supports an appealing hypothesis ("Microsoft's crypto is slow") is
exactly the one to repeat before writing it down; the wrong number was three times the right one and
pointed at a multi-week piece of work.

## Interop was never the obstacle

An earlier note claimed a P/Invoke per SSH packet would eat into any OpenSSL gain. That was wrong.
The plug-in already sets `DisableRuntimeMarshalling`, so blittable spans pass straight through, and
`SuppressGCTransition` (or a raw function pointer with `CallConvSuppressGCTransition`) removes the
GC mode switch, leaving little more than a call instruction. But the decisive point is simpler: at
1.4–32 KB blocks the hashing itself takes 6–130 µs, so even an ordinary transition of tens of
nanoseconds is under 1% and there is nothing to optimize.

Which is fortunate, because `SuppressGCTransition` would not be available here anyway. Its
documentation lists requirements the method "must have all of", the first being that the native
function "always executes for a trivial amount of time (**less than 1 microsecond**)" — a 130 µs
hash is over a hundred times outside that — and lists the consequences of invalid use as "GC
starvation. Immediate runtime termination. Data corruption." Whether *duration alone* could really
produce the latter two is doubtful; they read like consequences of the other listed violations
(blocking syscalls, callbacks into the runtime, exceptions, locks). So the 1 µs bar is probably
conservative for a pure-compute call. It is still a documented requirement, this is a data path
inside a background-task host where a wedge is expensive to diagnose, and the gain being chased is
under 1% — so a generous reading of it would be a poor trade even if the reading is right.

Two notes that close off the obvious ways to reopen that, both worth having because both are the
argument someone would reach for.

**"But the runtime itself does long native calls without transitioning."** It may well, and the CLR
coding guide holds runtime code to the same principle — "in cooperative mode, you are blocking other
threads from GC so you must avoid long or blocking operations" — but it also gives that code an
escape our P/Invoke does not have: `GCX_COOP`/`GCX_PREEMP` holders, and the raw
`GetThread()->EnablePreemptiveGC()`, let internal code drop to preemptive mode around exactly the
slow part and come back. So the runtime's long native work need not be uninterruptible; ours would
be. The 1 µs bar is not a claim that 130 µs of cooperative mode is fatal, it is the consequence of
having no way to reach a safe point until the native function returns.

**A hook can retroactively violate the contract.** "Does not call back into the runtime" is a
property of whatever actually runs behind that entry point on someone else's machine, not of the
function we chose to call. Security software, telemetry and instrumentation libraries hook exactly
this kind of API — a registry or crypto entry point — and a hook may re-enter managed code where the
original never did. Reported from experience with such a hook on `RegQueryValueExW`, which tripped
the "transition into the runtime without transitioning out" MDA when internal runtime code called
through it. So a suppressed transition on a widely-hooked function is a bet on other people's
software, which is not a bet to take for under 1%.

## Verdict

- **Do not ship OpenSSL.** ~1.1–1.2×, within the noise floor of this machine, against a permanent
  obligation to track libcrypto CVEs inside an app package.
- **Do prefer AEAD**, which is done: the fork now offers `aes256-gcm`, `aes128-gcm` and
  `chacha20-poly1305` ahead of the CTR suites, and RFC 4253 §7.1 makes the client's order decide.
- **For a server that offers no AEAD suite the MAC cost stays**, and OpenSSL would shave ~20% off it
  — about 2 points of process CPU, or 0.02 of a core. Still not worth the dependency.
- **Do not hand-roll SHA-256.** Even if a faster implementation were achievable, crypto lacks the
  eyeballs here to be confident it is correct, and the ceiling is 1.2× of a 12% cost.

## Reproducing

`docs/profiling/macbench.cs` is a .NET 10 file-based app, so no project is needed:

```
dotnet run docs/profiling/macbench.cs 32768
```

It prints `sha256 hmac gcm` in MiB/s. Run it on Windows and under WSL and interleave the rounds. The
machine must be idle — see above.

## Correction and production result (2026-08-21)

The AEAD reorder shipped, the server took it — `cipher in aes256-gcm@openssh.com out
aes256-gcm@openssh.com, mac in none (AEAD) out none (AEAD)` — and a profile of the result corrects
two things above.

### The block size was wrong, and it moves both conclusions

This document reasoned about 32 KB blocks, on the grounds that a bulk download has the server
sending near-maximum SSH packets. That was an assumption, and the production profile disproves it.
Measured AES-GCM cost is **1.89 ms/MiB**, against benchmark rows of 1.68 at 1400 bytes, 1.41 at 8 KB
and 0.46 at 32 KB. The traffic is MTU-sized, not 32 KB — which stands to reason, since the stack
sends one SSH channel-data message per IP packet.

Re-measured at 1400 bytes, same OS to avoid the problem in the next subsection, OpenSSL's lead is
**larger** than the headline figure: SHA-256 222–231 against CNG 147–219, AES-GCM 1891–1906 against
CNG 1040–1465, so roughly 1.3–1.5× rather than 1.1–1.2×. Per-call overhead matters more at 1.4 KB
than the algorithm does, and the two libraries pay it differently.

The verdict does not change, and gets stronger in absolute terms: after the reorder crypto is 1.7%
of process CPU, so 1.4× of it is worth about half a point. What changes is that the earlier figure
was quoted for a block size the tunnel does not use.

### The WSL method breaks down at small block sizes

Running the same managed code on Windows and under WSL is a clean way to isolate CNG from OpenSSL —
at 32 KB. At 1400 bytes it produced nonsense: CNG appeared to *beat* OpenSSL, by 2–3× on AES-GCM
(1040–1465 against 179–606), and the WSL arm swung 3.4× between rounds. At this size the benchmark
makes ~90,000 calls a second, so what it measures is WSL2's per-call overhead, not the algorithm.
The document's original caveat — "WSL2 is a VM, so its arm carries whatever overhead that adds; for
a pure-compute test that should be negligible but it is not zero" — turned out to be the
load-bearing sentence. Compare same-OS (`openssl speed` against the .NET benchmark on Windows) when
the block is small, and accept the slightly less clean harness in exchange.

### AEAD, measured rather than projected

The same iperf-style download, before and after, with the caveat that the after-run was intermittent
(~264 MiB over the 34 s trace, ~65 Mbit/s, against ~756 MiB and ~170 Mbit/s before) — so compare
shares and per-byte costs, not absolute cores:

| | CTR + HMAC | AES-GCM |
|---|---|---|
| `bcryptprimitives.dll` | 4.77 s | 0.50 s |
| managed cipher scaffolding (`CtrImpl`) | 0.58 s | none |
| crypto share of process CPU | **12.7%** | **1.7%** |
| crypto per byte | 7.08 ms/MiB | 1.89 ms/MiB (**3.7×**) |

So the earlier "~9× faster per byte" was the 32 KB benchmark ratio for GCM against HMAC alone. The
real gain is 3.7×, because the old path's cost was CTR *plus* HMAC and GCM replaces both, and
because MTU-sized blocks amortise per-call overhead far less well than 32 KB ones. Still the largest
single win available on this path, and it needed no fallback logic — but 3.7×, not 9×.

Not comparable across this pair, and worth stating so nobody reads it as a regression: total process
CPU per byte got *worse* (49.5 → 113 ms/MiB), because the after-run moved a third of the data at a
third of the rate with 11–17 flows instead of one, so the stack's per-second and per-flow costs
amortise over far fewer bytes. A clean before/after on total CPU needs two steady runs at the same
rate.
