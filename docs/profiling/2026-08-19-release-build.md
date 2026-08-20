# The build was the bottleneck: Release doubles the tunnel (2026-08-19)

Four Visual Studio CPU sessions — random browsing and `iperf3 -R` through the tunnel, once on the
Debug build and once on Release — settle where the tunnel's CPU actually goes, and correct the
conclusion of `2026-08-18-tunnel-cpu-cap.md`, whose numbers were all Debug numbers taken from a
single stack snapshot per thread.

The headline is embarrassing and cheap: **`Configuration=Debug` compiles the native code with ILC
optimizations off**, and every throughput figure in this project's history — 630 kbit/s through
165 Mbit/s — was measured that way.

## Why Debug is not "Debug" under Native AOT

`Configuration=Debug` sets `Optimize=false`. `Microsoft.NETCore.Native.targets` passes ILC an
optimization switch only when `Optimize` is true:

```
<IlcArg Condition="$(Optimize) == 'true' and $(OptimizationPreference) == 'Size'" Include="--Os" />
<IlcArg Condition="$(Optimize) == 'true' and $(OptimizationPreference) == 'Speed'" Include="--Ot" />
```

With no `OptimizationPreference` set, Release gets plain `-O`. Verified directly in the generated
response files (`obj\<cfg>\...\native\*.ilc.rsp`): Debug carries `-g` and **no** optimization flag —
and ILC's default optimization mode is *none*. For a JIT assembly a Debug build still gets an
optimizing JIT at runtime; under AOT there is no second chance. Native binary size shows it:
24.9 MB Debug versus 13.2 MB Release. `-g` is passed in both, so Release still yields a matching
PDB and profiles exactly the same way.

The fingerprint in the Debug profile is unmistakable: `Span<byte>.get_Length`, `Span.Slice`,
`ReadOnlySpan..ctor`, `MemoryMarshal.Read<UInt64>` and `BinaryPrimitives.ReverseEndianness` all
appear as out-of-line leaf functions with real sample weight — **11.4 s of the 22.0 s our own binary
burned, 21% of the whole process**, in helpers that inlining reduces to a `bswap` or a pointer add.
In the Release traces that entire category measures **0.0 s**.

## Numbers

Throughput is wire bytes from the plug-in's own cumulative delivery counter, diffed across 30 s
report windows — independent of iperf's accounting. The two sessions are 4.5 h apart, so this is not
a controlled A/B on identical line conditions; the CPU-per-bit column does not depend on the line at
all.

| | Debug | Release |
|---|---|---|
| Best download window | 97.0 Mbit/s | **194.5 Mbit/s** |
| Profiled window | 97.0 Mbit/s | 161.8 Mbit/s |
| Process CPU | 1.59 cores | **1.00 core** |
| CPU per Mbit/s | 16.4 mcore | **6.2 mcore** (2.65× better) |
| Our own binary | 40.7% of process | **11.9%** |
| Uninlined trivial helpers | 21.1% of process | **0.0%** |

Per-byte cost of individual pieces, Release against Debug — note the absolute seconds fell while
carrying 1.67× the data:

| | Debug | Release | per byte |
|---|---|---|---|
| `TcpSegment.ComputeChecksum` | 6.95 s | 0.72 s | **16× cheaper** |
| T-Stack (`PacketPath.Run`) | 16.15 s | 6.43 s | 4.2× |
| T-Listen (`Session.MessageListener`) | 13.17 s | 6.26 s | 3.5× |
| Our `Decapsulate` handler | 0.76 s | 0.45 s | 2.9× |
| Platform injection (`VpnExeRioPumpPostSendBatch`) | 15.42 s | 17.54 s | 1.5× |

The checksum figure is the RFC 1071 64-bit rewrite finally compiling to what it was written as: in
Debug, `InternetChecksum.Accumulate` was 12.9% of the process inclusive, of which only 3.5 points
were the function itself and 9.2 were call overhead into `ReadUInt64BigEndian` and `Slice`.

## Where the CPU goes now

At 162 Mbit/s on the Release build (37.4 s of CPU over 37.3 s of wall):

- **Platform injection: 46.8%.** `VpnExeSocketRecvCompleteCallbackProcessDecapsulate` (52.9%) is
  dominated by `VpnExeRioPumpPostSendBatch` → `fwpuclnt` → WFP / NDIS / **NDISWAN** / **WANARP** /
  `rassstp` / tcpip — the platform pushing decapsulated packets up through the WAN miniport into
  Windows' own stack. Our handler underneath it, `VpnExecHlpDecapsulate`, is **1.2%**. This scales
  with packet count rather than bytes, and it is not ours to optimize; the only lever is fewer,
  larger packets.
- **HMAC: 12.1%** — now the largest cost we control, larger than our entire TCP/IP stack thread.
- **T-Stack: 17.2%** — `StackLoop.RunOnce` 10.7%, `PacketPath.DrainOutbound` 4.4%,
  `PlatformOwnedTransport.RingDoorbell` 1.5%. Within `SendSegment` (9.2%) the cost is now
  `InboundPacketSink.TryWrite` 6.8% (buffer acquire plus the copy), not packet building
  (`TcpSegment.Write` 1.9%).
- **T-Listen: 16.7%**, essentially all of it `ReceiveMessage`.
- **AES-CTR: 2.4%.**

## The cipher conclusion, corrected

`2026-08-18-tunnel-cpu-cap.md` said the ceiling "belongs to the cipher work" on the strength of one
stack snapshot that caught `HMACSHA256 → BCryptHashData`, and its own caveat — that per-thread shares
were not measured — turned out to be the operative fact. Two corrections:

1. **Crypto was never the ceiling.** In the Debug trace all crypto totalled 22% of process CPU
   against 21% wasted in uninlined helpers and 28% in platform injection.
2. **Optimization flipped which half of the crypto costs.** Debug showed AES `Decrypt` at 14.7%
   against the MAC's 7.5%, which read as "AES is the expensive one". Most of that AES figure was
   *managed CTR scaffolding* — `CTRCreateCounterArray`, `ArrayXOR`, `Vector<byte>..ctor` — which
   inlining erased. Release: **MAC 12.1%, AES-CTR 2.4%.** AES-NI is nearly free; SHA-2 on this
   machine is not.

### What that does and does not license (2026-08-20)

The cause turned out to be ours: the fork listed `aes*-ctr` **before** the AEAD suites, and RFC 4253
§7.1 selects the first algorithm on the *client's* list that the server also offers, so a server that
supports GCM still gave us CTR plus a separate MAC because that is what we asked for first. AEAD is
now offered ahead of CTR, which needs no fallback logic — a server without it matches further down
the same list.

Three limits on reading that as a fix:

1. **It helps only against servers that offer an AEAD suite.** Plenty of deployments run older or
   restricted SSH servers that offer none. For those the MAC pass stays exactly as measured, and this
   change does nothing for them. The general problem is not solved, only avoided where the far end
   cooperates.
2. **The remaining cost is real work, not overhead.** `HMACSHA256` is the BCL's, so the time is inside
   `bcryptprimitives.dll`; BouncyCastle appears only as a fallback for GCM/ChaCha/ECDSA, and
   `AesGcm.IsSupported` is true here so even GCM is native. There is no managed layer to delete.
3. **Its size is specific to this CPU.** An i7-6700HQ has AES-NI and PCLMULQDQ but no SHA
   extensions, so GHASH is hardware and SHA-256 is not: ~756 MB hashed in 4.54 s is ~166 MB/s on one
   thread, software speed. With SHA-NI the same work would be several times cheaper and would not
   have been the top item.

And the absolute figure deserves repeating, because percentages of process CPU invite
misreading: 12.1% of the process is **0.12 of one core** on an 8-thread machine, at 162 Mbit/s.
Whether that is worth further engineering on the non-AEAD path is genuinely open.

A log line at connect now records the negotiated kex, host key, ciphers and MACs, so the suite is
observable from the log instead of inferred from a profile.

## Method

Same pipeline as the previous doc, plus what it cost to learn:

- Visual Studio `.diagsession` files are OPC/zip; the payload is `sc.user_aux.etl`, a system-logger
  session carrying `Sampled Profile` (1 kHz per core) plus `StackWalk`. Analysed offline with
  `xperf -a profile -detail` (leaf, per function) and `-a stack -butterfly -process` (inclusive,
  callers and callees).
- **The sampling is system-wide; only the profiled process gets stacks.** So `-symbols` resolves
  symbols for *every* process in the trace. Pointing `_NT_SYMBOL_PATH` at a symbol server pulled
  **990 MB**, 631 MB of it `msedge.dll.pdb`, none of it relevant. Use a local-only symbol path
  (`<publish dir>;C:\Symbols`) and let irrelevant modules stay unresolved; module-level attribution
  already names them. `_NT_SYMCACHE_PATH` defaults to `C:\SymCache` and holds derived `.symcache`
  indexes, not PDBs — it is not a download.
- **Interrupt and DPC time is not a confound here**: 98.35% of the process's samples root at
  `RtlUserThreadStart`, and all interrupt/DPC roots together are 0.3%. The large driver share really
  is synchronous work reached from our own threads.
- Thread roles read off the roots: `PacketPath.Run` under `Thread.StartThread` is T-Stack;
  `Session.MessageListener` under `Task.ExecuteWithThreadLocal` is T-Listen (SSH.NET starts it as a
  `LongRunning` task, so it gets a dedicated thread); `TppWorkerThread` is the platform's callbacks
  plus our own worker tasks.

## Also observed

- **`MaximumLiveChannels = 128` is now what limits browsing.** The Release browsing session logged
  578 × `Refusing a channel … 128 channels already live`, flows reaching 102, while the process spent
  7.8 s of CPU across the entire 162 s trace. Not a regression — the Debug session refused 874 — but
  nothing above the cap is saturated any more.
- **A 39 ms channel reap.** One browsing window reported `reaps 0.3/s in avg 38950 us`, twenty times
  the worst figure in the previous doc's addendum. It ran on a worker, which is exactly what the
  `Task.Run` hop exists for: inline on T-Stack that would have been a 39 ms stall of the packet path.
- Release introduced no new failure mode: the channel-teardown `NullReferenceException` (8),
  channel-open timeouts (132) and refusals all appear in the Debug log in larger numbers.
