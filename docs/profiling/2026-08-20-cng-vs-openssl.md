# Is Windows CNG leaving crypto performance on the table? (2026-08-20)

**Question.** The MAC pass measured 12% of the plug-in host's CPU (see
`2026-08-19-release-build.md`). Microsoft's CNG is not always the best-optimized implementation, so
would shipping OpenSSL in the package buy anything?

**Answer: no, not enough to be worth it.** CNG is within ~1.1–1.2× of OpenSSL on this CPU for
SHA-256, HMAC-SHA256 and AES-GCM alike. Shipping and patch-tracking libcrypto for that is a bad
trade for a security-critical dependency. The real win is not the library, it is **not needing the
MAC at all**: AES-GCM runs ~9× faster per byte than HMAC-SHA256 here, on *either* backend, which is
what makes the AEAD-first cipher order worth having.

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

Two caveats on the method itself. WSL2 is a VM, so its arm carries whatever overhead that adds; for a
pure-compute test that should be negligible but it is not zero. And this is a laptop: run-to-run
spread is roughly ±20%, which is the same order as the difference being measured, so treat the ratios
as "about parity" rather than as precise figures.

## Numbers

Six interleaved rounds, 32 KB blocks, MiB/s, median with range:

| | CNG (Windows) | OpenSSL (WSL) | ratio |
|---|---|---|---|
| SHA-256 | 230 (197–265) | 264 (167–285) | 1.15× |
| HMAC-SHA256, persistent instance | 240 (168–265) | 293 (268–301) | 1.22× |
| AES-256-GCM encrypt+tag | 2161 (1528–2388) | 2348 (1994–2404) | 1.09× |

A seventh Windows run, taken later on a fully idle machine, measured CNG at **262 / 270 / 2445** —
at or above the OpenSSL medians for all three. That is one unpaired sample rather than another round,
but it points the same way: on this CPU the two backends are close enough that ordinary machine noise
swamps the difference.

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

An earlier note claimed a P/Invoke per SSH packet would eat into any OpenSSL gain. That was wrong on
two counts. The plug-in already sets `DisableRuntimeMarshalling`, so blittable spans pass straight
through, and `SuppressGCTransition` (or a raw function pointer with `CallConvSuppressGCTransition`)
removes the GC mode switch, leaving little more than a call instruction. More to the point, at
1.4–32 KB blocks the hashing itself takes 6–130 µs, so even an unsuppressed transition of tens of
nanoseconds is under 1%. Note also that `SuppressGCTransition` is contraindicated for calls this
long: it delays GC suspension for the duration of the native call, and 130 µs is not the brief call
the attribute is meant for.

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
