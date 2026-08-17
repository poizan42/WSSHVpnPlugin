# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Windows `IVpnPlugIn` provider that carries VPN traffic over SSH. UWP on modern .NET
(`net10.0-windows10.0.26100.0`, `UseUwp`, `PublishAot`) — not .NET Native, and not WinUI 3.

## Building

`dotnet build` works **only** for `PoiTech.WSSHVpnPlugin.VpnPlugin`. The app and packaging projects
need Visual Studio's MSBuild: the UWP XAML compiler targets don't run under the `dotnet` CLI, and the
failure is misleading — "Program does not contain a static 'Main' method" plus a pile of
`InitializeComponent does not exist`. Don't chase those errors; switch to MSBuild.

Build everything (from a Developer Command Prompt, so `vswhere.exe` is on `PATH` — the Native AOT
link step shells out to it and otherwise fails with `MSB3073 ... exited with code 123`):

```
MSBuild.exe PoiTech.WSSHVpnPlugin.Package\PoiTech.WSSHVpnPlugin.Package.wapproj /p:Platform=x64 /p:Configuration=Debug /restore
```

Deploy locally — Developer Mode only, no signing, and restricted capabilities are accepted on this
path (verified):

```
Add-AppxPackage -Register PoiTech.WSSHVpnPlugin.Package\bin\x64\Debug\AppxManifest.xml
Get-AppxPackage *3703e6b2-f1f9-447d-b506-da47be3094ff* | Remove-AppxPackage
```

Deploy-loop practicalities, each learned by hitting it:

- The package registers the **loose build output**, so a running host or app locks the files and
  fails the build's copy step. Run a kill loop for `PoiTech.WSSHVpnPlugin.VpnPlugin` and
  `PoiTech.WSSHVpnPlugin.App` for the build's duration. A deploy also tears down the user's live
  tunnel — coordinate before building when a session is up.
- Re-registering in place is enough for code changes. A **manifest change** fails it with
  `0x80073CFB`; that needs `Remove-AppxPackage` + register, which resets the
  `broadFileSystemAccess` consent (see below) **and wipes `wsshvpn.log`** — copy the log out first
  if anything in it still matters.

## Tests

`PoiTech.WSSHVpnPlugin.Net.Tests` covers the stack, and is the only fast loop in the repo — plain
`net10.0`, no WinRT, no deploy, under a second:

```
dotnet test PoiTech.WSSHVpnPlugin.Net.Tests\PoiTech.WSSHVpnPlugin.Net.Tests.csproj
```

It drives `StackLoop` and `DnsRelay` with synthetic packets through `StackHarness.cs`'s fakes
(`FakeChannel`, `FakeChannelFactory`, `FakeSink`, `FakeClock`, `Packets`) — use those rather than
writing new ones. Anything in the stack that can be reproduced from a packet belongs here and not in
a deploy: the plug-in half costs a package build, a registration and a VPN activation per attempt.

The `SSH.NET` submodule has its own suite; fork changes should be validated there:

```
dotnet test SSH.NET\test\Renci.SshNet.Tests\Renci.SshNet.Tests.csproj
dotnet test SSH.NET\test\Renci.SshNet.Tests\Renci.SshNet.Tests.csproj --filter FullyQualifiedName~ChannelDirectTcpip
```

The suite is **2363 tests, 13 skipped**. Two of them — `ConnectAsync_HostNameInvalid_*` and
`ConnectAsync_ProxyHostNameInvalid_*` — depend on the local resolver rejecting invalid host names,
so they pass or fail with the network rather than with your changes. Don't chase them, and don't
treat a fixed pass count as the baseline.

`StreamSocketSshTransportTest` is the only coverage of the transport the plug-in actually uses —
everything else drives `Session` over `SocketSshTransport`, which production never instantiates. It
runs in under a second on loopback, so its `[Timeout(1000)]` is deliberate: the tests exist to catch
a read that never returns, and waiting long defeats them.

`Renci.SshNet.IntegrationTests` needs Docker (testcontainers). The submodule treats warnings as
errors in Release and under CI, and applies StyleCop/Meziantou/Sonar analyzers, so changes there
have a much stricter bar than this repo's own code.

## Architecture

Four projects plus a test project and the fork. The split that matters is **`.Net` versus
everything else**: the stack is plain `net10.0` with no WinRT, so it can be tested in a second, while
anything touching the platform costs a package build and a VPN activation per attempt. Keep new logic
on the `.Net` side of that line wherever it has a choice.

- **`PoiTech.WSSHVpnPlugin.Net`** — the user-space TCP/IP stack. No WinRT, no SSH: it reaches both
  through the `IByteChannel` / `IByteChannelFactory` / `IPacketSink` / `IStackClock` seams, which is
  what lets the whole thing run on synthetic packets with no session and no threads.
- **`PoiTech.WSSHVpnPlugin.Net.Tests`** — MSTest against those seams. See **Tests** above.
- **`PoiTech.WSSHVpnPlugin.VpnPlugin`** — the plug-in, and the only place WinRT and SSH meet the
  stack. A CsWinRT component (`CsWinRTComponent`), so **public types must be WinRT-compatible**; keep
  everything except `SSHVpnPlugin` and `VpnBackgroundTask` `internal`.
- **`PoiTech.WSSHVpnPlugin.App`** — UWP XAML app whose only real job is creating the VPN profile via
  `VpnManagementAgent`. There is no system UI for provisioning a plug-in profile, so this is the only
  way one gets created.
- **`PoiTech.WSSHVpnPlugin.Package`** — wapproj; owns `Package.appxmanifest`.
- **`SSH.NET`** — submodule, fork of upstream. It exists because
  `Session.CreateChannelDirectTcpip`, `ISession`, and `IChannelDirectTcpip` are all `internal`
  upstream.

`PacketPathAdapters.cs` is where the seams are implemented (`DirectTcpipByteChannel`,
`SshByteChannelFactory`, `InboundPacketSink`, `MonotonicClock`) — the one file to read to see how the
two halves join.

### The activation chain

Three declarations have to agree, and each was a separate build failure to discover. Changing one
without the others breaks packaging or silently breaks activation:

1. There is **no `windows.vpnPlugin` extension category**. A VPN plug-in is a
   `windows.backgroundTasks` extension carrying `<uap:Task Type="vpnClient" />`, declared on a second
   `<Application Id="Plugin">` entry with `AppListEntry="none"`.
2. That `EntryPoint` needs a matching package-level `windows.activatableClass.inProcessServer`
   registration, or packaging fails with *"not allowed to have EntryPoint=... without
   ActivatableClassId"*.
3. Its `<Path>` must name a binary exporting `DllGetActivationFactory`. CsWinRT's generator emits one
   into the component, and `PoiTech.WSSHVpnPlugin.VpnPlugin.csproj` carries
   `UnmanagedEntryPointsAssembly` + `<LinkerArg Include="/EXPORT:DllGetActivationFactory" />` to keep
   ILC from trimming it and to export it. Verify with `dumpbin /exports` if activation ever stops
   working.

Paths in the manifest are `<project>\<project>.exe` — the wapproj nests each payload in a subfolder
named after its project, and `$targetnametoken$` resolves to the *wapproj* name here, so it can't be
used.

### The plug-in is its own executable, and must be

**The plug-in and the app are separate binaries and separate processes.** This is not cosmetic and it
cost most of an evening to establish:

- **Sharing the app's executable put the tunnel inside a XAML application's process**, because Native
  AOT linked the component in and the manifest pointed at the app. When PLM suspended that
  application, `DXamlCore::OnAfterAppSuspend` → `ReferenceTrackerManager::TriggerCollectionForSuspend`
  → `ReferenceTrackerHost.DisconnectUnusedReferenceSources` called **`GC.Collect()` inside the VPN
  host**. That collection deadlocks: `TrackerObjectManager.WalkExternalTrackerObjects` runs
  `FindReferenceTargetsCallback`'s class constructor *inside the GC callout*, which allocates, which
  waits for the collection it is already inside. Windows logs **`Application Hang`** — "stopped
  interacting with Windows and was closed" — and kills the host **45–75 seconds after every connect**.
  Traced from live `cdbX64 -pv` thread stacks; there is no crash dump, because a hang is not an
  exception. Fixing it took the host out of XAML, and 24 samples across a 3-minute run then showed no
  deadlock and no XAML frames at all.
- **`backgroundtaskhost.exe` is not available.** Omitting `Executable` on the extension so the DLL
  would be hosted generically fails registration with **`0x80080204`, "a task of this type requires a
  custom background task host"**. A `vpnClient` task must name a host binary; the only choice is
  *which* one.
- So `PoiTech.WSSHVpnPlugin.VpnPlugin` is a `WinExe` with its own `Program.Main`, and both the
  extension's `Executable` and the `inProcessServer` `<Path>` name it. `Main` is
  `CoreApplication.RunWithActivationFactories(...)` — what `Application.Start` did, minus XAML.
- **`IGetActivationFactory` is in `Windows.Foundation`**, not `Windows.ApplicationModel.Core`, and the
  class implementing it **must be public**. As a private nested class it compiles and then dies at
  runtime with `E_NOINTERFACE` from `CreateCCWForObjectForABI`: CsWinRT only generates COM callable
  wrappers for authored — that is, public — types. That is the one deliberate exception to keeping
  everything but `SSHVpnPlugin` and `VpnBackgroundTask` internal.
- The app project **must not reference the plug-in**. It never used a type from it; the reference
  existed only to make AOT link and re-export the factory, which is what caused all of the above.

**`broadFileSystemAccess` consent resets on every reinstall.** `Remove-AppxPackage` +
`Add-AppxPackage -Register` silently clears it, and the next connect fails with
`ConnectProfileAsync: ServerConnection` and an `UnauthorizedAccessException` from `ReadThroughBroker`
in the log. Re-enable it under Settings > Privacy & security > File system. Removing the package also
**wipes `wsshvpn.log`**, so a failure right after a reinstall may leave nothing to read.

### Runtime flow

`VpnBackgroundTask.Run` is what the platform activates, once per event (connect, encapsulate,
decapsulate, keep-alive, disconnect). It must hand `VpnChannel.ProcessEventAsync` the *same*
`IVpnPlugIn` instance every time — the plug-in holds the live SSH session and partially reassembled
state — so the instance lives in `CoreApplication.Properties`, which outlives an activation but not
the host process. Exceptions must not escape `Run`; they tear down the host and leave the platform
without a response.

### The transport socket belongs to the platform

Established by disassembling `Windows.Networking.Vpn.dll` after a long spike. Do not re-litigate this
by experiment; each attempt costs a deploy, and the channel is **single-shot** (after one rejected
`Start*` every later call returns `E_ILLEGAL_METHOD_CALL`, so one activation = one experiment).

- `AssociateTransport` registers the socket as a **ControlChannelTrigger**, which is why it must be
  unconnected. `Start*` then calls `WaitForPushEnabled`, `TakeTransportOwnership` and
  `VpnExeChannelCreate`, after which **the VPN service reads and writes that socket**. A plug-in
  cannot run its own protocol on it — SSH bytes get consumed by the platform's reader.
- So the SSH session runs on a **separate socket the platform never sees**, bound to the physical
  interface, and the platform gets a **loopback dummy socket** as its transport.
- **`E_OUTOFMEMORY` from `Start*` means the assigned IPv6 address list was empty.** Bisected to a
  single variable: with `mtu 1400` / `maxFrameSize 1500` unchanged, adding one IPv6 address
  (`fd00::2`) turns a hard failure into `StartWithMainTransport accepted`. Assign at least one address
  for **both** families or the call fails with a resource error that has nothing to do with resources.
  This cost most of a day, because it looks like anything but an argument problem.
  Note the separate, opposite hazard already recorded below: inclusion *routes* for a family with no
  assigned address hang the platform. Address without routes is fine; routes without address is not.
  Also disproved along the way, so nobody re-runs them: the delay before `Start` is irrelevant
  (307 ms works), and so is "it only works on the second attempt" (a cold first connect works).
  Two theories that were confidently wrong and are recorded so nobody rebuilds them:
  "the socket was already connected" (Maple connects too, and ships), and "the CCT broker refuses
  over RPC" — **`WaitForPushEnabled` returns `S_OK`**, observed under `cdbX64`, so the whole control
  channel trigger path including slot allocation works. `TakeTransportOwnership` also returns 0.
  The transport shape is irrelevant: a loopback datagram pair and a real remote TCP connection fail
  and succeed identically. The CCT-broker theory's last artifact, a `<Task Type="controlChannel" />`
  manifest declaration, was removed and verified unnecessary: connect and full-speed traffic work
  with `vpnClient` as the only declared task type.
- **Debugging `Start` is practical.** `Windows.Networking.Vpn.dll` has public PDB symbols
  (`VpnChannelImpl::StartInternal`, `TakeTransportOwnership`). The host is created per activation and
  exits on failure, so `<StartDelaySeconds>` in the profile makes it wait long enough to attach
  `cdbX64 -p`. Tell the host from the UI by command line: the UI carries `-ServerName:App.AppX...`.
- **`Encapsulate` must rotate its list, not read it.** Take each buffer with `RemoveAtBegin()` and
  `Append()` it back to the **same** `packets` list — never to `encapsulatedPackets`, which stays
  empty because the SSH session owns the wire. Both shipping implementations do exactly this.
  Merely enumerating the list looks harmless and is not: the platform delivered one burst during
  connect and then nothing ever again, which is what a plug-in that never returns its buffers looks
  like. Symptom to recognise: the tunnel is up, routes are correct, `Find-NetRoute` picks the tunnel,
  keep-alive activations keep arriving, and no packet is ever offered.
- **`GetVpnReceivePacketBuffer()` works on a worker thread**, so the inbound queue can carry platform
  buffers and cost one copy rather than two.
- The platform starts reading the associated transport at `AssociateTransport`, before `Start`:
  `Decapsulate` fired with the SSH server's 42-byte identification string while `Start` was still
  pending.
- Always `AssociateTransport` before `Start*`. `StartWithMainTransport` compares what you pass
  against what you associated (a vector at `this+0xA8` that only `AssociateTransport` writes), so
  calling it on a virgin channel dereferences NULL and kills the background-task host.
- `SetErrorMessage` is documented "Not supported" — use `TerminateConnection`.

### Debugging the background task

There is no console and no debugger attached. What worked, in order of usefulness:

- **WER LocalDumps** for crashes: set `HKLM\...\Windows Error Reporting\LocalDumps\<exe>` (needs
  elevation), reproduce, then analyse with `cdbX64.exe` — the Store WinDbg build. The Windows Kits
  `cdb.exe` fails to start on this machine; `cdbX64.exe` on `PATH` works.
- **Non-invasive attach for hangs**: `cdbX64 -pv -p <pid> -c "~*k"`. This is what found
  `WaitForPushEnabled`.
- **ETW**: `logman create trace ... -p "{E5FC4A0F-7198-492F-9B0F-88FDCBFDED48}"` (Networking VPN
  Plugin Platform) works without elevation, but only gives coarse states — Connecting, Negotiating
  Network, Abort. The detailed errors are WPP and need a TMF to decode.

### The central design constraint

SSH cannot carry raw IP datagrams. Its forwarding primitive (`direct-tcpip`) is a byte stream to a
host and port, so there is no packet-for-packet encapsulation and the usual `Encapsulate` /
`Decapsulate` symmetry does not apply:

- `Encapsulate` consumes IP packets and returns **nothing** — the SSH session owns the wire, not the
  platform. A user-space TCP/IP stack has to demultiplex flows onto `direct-tcpip` channels.
- `Decapsulate` is the *inbound* path, not a mirror of `Encapsulate`. See below.
- UDP and ICMP need a separate answer; plain SSH has no primitive for either. **DNS is the exception
  that had to be solved**, because assigning DNS servers pins the whole machine's name resolution to
  the tunnel the moment it starts — so UDP/53 going nowhere does not degrade, it breaks every name on
  the system. `DnsRelay` carries each query over its own `direct-tcpip` channel with RFC 7766's
  two-byte length prefix and turns the reply back into a datagram. Replies too large for one datagram
  come back truncated with `TC` set, which makes the client retry over TCP — carried natively. Other
  UDP and all ICMP are still dropped.

### The outer tunnel transport is a loopback dummy

The platform takes **exclusive ownership** of whatever is passed to `AssociateTransport`: it registers
the socket as a ControlChannelTrigger, then `Start*` calls `WaitForPushEnabled`,
`TakeTransportOwnership` and `VpnExeChannelCreate`, after which the VPN service reads and writes it
itself. An SSH session running over that socket has its bytes stolen — we watched the banner come back
corrupted. Established by crash dump, live stack and disassembly of `Windows.Networking.Vpn.dll`; do
not re-derive it.

So `LoopbackTransport` hands the platform a cross-connected pair of `DatagramSocket`s on `127.0.0.1`
that carries nothing, and SSH runs on a socket of its own. Load-bearing details:

- **Order**: `AssociateTransport` first and on an *unconnected* socket, then bind both, then
  cross-connect, then `StartWithMainTransport` passing the same socket. Calling `Start*` on a channel
  that never had `AssociateTransport` dereferences NULL and kills the host; connecting before
  associating earns `E_OUTOFMEMORY` from the CCT broker, which is not about memory.
- **Datagrams, never a listener.** TCP cannot cross-connect, so a `StreamSocket` dummy would need a
  `StreamSocketListener` — the one loopback shape whose app-container behaviour is doubtful. Loopback
  itself needs no exemption: the check passes when both endpoints share the package SID.
- **Inbound injection goes through `Decapsulate`, woken by a doorbell.** Writing one byte to the back
  socket makes the platform raise the event. The producer calls `GetVpnReceivePacketBuffer()` on its
  *own* thread, writes the packet directly into that buffer and queues it (`InboundPacketQueue`);
  `Decapsulate` only appends, which is what returns the buffer. One copy, not two. The back socket is
  a classic UDP `Socket`, not a `DatagramSocket`: it only ever sends, and the WinRT stream adapter
  cost an async-operation RCW plus a reflection-computed interface GUID per ring, sampled live.
- **Ring per empty→non-empty transition, never per batch** — see the activation-watchdog section
  below for why per-batch rings kill the host at line rate. The old per-batch rule existed because
  transition-only ringing once stalled forever ("nothing drains, so it never empties, so no later
  enqueue is a transition"); that deadlock is closed by `Decapsulate`'s exit ring (a drain that
  leaves work behind rings on its way out), which makes a non-empty queue always owed a visit by
  induction, and a 250 ms safety re-ring in the stack loop covers an actually lost datagram.
- **`channel.Stop()` must be called synchronously inside the `Disconnect` callback — and only
  there.** The docs mean it: `IVpnPlugIn.Disconnect` "instructs the VPN plug-in to ... destroy the
  VPN channel", and `Stop` is the destroy call. Called in that window it returns in ~0 ms, the
  disconnect activation completes in half a second, and — the payoff — **the connection-long
  activation finally completes too** (`VpnExeWaitForTaskToIdle` was waiting for exactly this), so
  the host is never condemned and no `ExecutionTimeExceeded` cancellations appear at all.
  Everywhere else `Stop` can never return, and the deadlock is the platform's own, named from a
  dump taken inside the block (public symbols, disassembly verified):
  `VpnChannelImpl::DisconnectInternal` runs on the same thread *after* the callback returns,
  acquires the channel's SRW lock (`this+0xE8`) and then — only when the transport vector is still
  populated, i.e. only when the plug-in did not stop first — virtually calls
  `VpnChannelImpl::Stop`, whose first act is to acquire the same non-reentrant lock. That fallback
  self-deadlocks the disconnect activation inside `ProcessEventAsync` forever; a late `Stop()` of
  ours just queues a second victim behind it (both were on-stack in the same dump, blocked at
  `Stop+0x5b`, `LockExclusive`), and only host death resolves the disconnect — which is why, in
  the non-conforming era, `DisconnectProfileAsync` completed exactly when the host exited. The
  in-callback `Stop` is safe only with no platform buffers in our hands (`IsFinished`), which a
  clean disconnect satisfies because the stack thread is joined first; otherwise the old
  choreography still runs — close the queue, ring once more, let `Decapsulate` finish the teardown,
  `OnStopWatchdog` reporting whether that call arrived. The bounded wait around the in-callback
  `Stop` (8 s, then retire) is armor, not expectation: it has measured 0 ms every time.
  (Curiosity from the same disassembly: `Stop` checks a WIL flag literally named
  `Feature_VPN_BugFixes_25A` right after taking the lock — Microsoft may have a staged fix for
  this family of bugs.)
- **Never a literal `0.0.0.0/0` inclusion route** — recorded in the reference implementation as looping
  back through the tunnel even from a bound socket. Use `0.0.0.0/1` + `128.0.0.0/1`. And only add
  routes for a family that has an assigned address, or the platform hangs.
- **`ExcludeLocalSubnets` does not keep the client's own LAN out of the tunnel.** Measured: with it
  set, flows to the machine's own `/24` still arrive at `Encapsulate`, carrying the *tunnel* source
  address — while `Get-NetRoute` shows the subnet on-link via the physical NIC at a better metric and
  `Find-NetRoute` picks that NIC. The routing table is right and something above it redirects anyway,
  so a route-table reading will tell you the opposite of what happens. The cost is real: every such
  flow becomes a channel open the SSH server cannot serve, and each one blocks until the SSH timeout.
- **`Ipv4ExclusionRoutes` *does* work, and is the fix for the above.** Measured across two runs of
  comparable length with nothing else changed: 11 flows to the client's own subnet before, 0 after,
  and no other flow affected. The route is accepted without complaint — no `WSAEACCES`, which is what
  the reference implementation recorded when using this API for a different purpose (keeping the SSH
  server itself reachable), so that failure does not generalise. Exposed as `<ExcludeRoute>` and kept
  configurable rather than made a blanket rule about private addresses: routing a *remote* private
  range in is the whole point of a VPN and uses the same machinery, so the two cases can only be told
  apart by the person configuring it.
- **SSH is source-bound** to a chosen interface (`OutboundInterface`), not kept out with
  `Ipv4ExclusionRoutes` (which returned `WSAEACCES` for that purpose in the reference implementation;
  ours is untested for it, and the exclusion of ordinary subnets above works fine).
  `GetInternetConnectionProfile` is useless here —
  its "preferred interface" becomes the tunnel. The heuristic cannot tell our tunnel from another
  VPN's TAP adapter, so `<NetworkAdapter>` in the profile is a real requirement when nesting, not a
  nicety.

### The 90-second activation watchdog, and the event prolog that trips it

The hardest hunt after the throughput ladder: at sustained 100+ Mbit/s the host died every few
minutes — the "dead replacement host" mystery, finally solved. Every belief below was bought with a
failed experiment, so check here before re-deriving any of it:

- **Every background-task activation must complete within 90 seconds** — measured to the
  millisecond, repeatedly, as `BackgroundTaskCancellationReason.ExecutionTimeExceeded` followed
  five seconds later by *"did not complete in response to a cancel notification"* in the
  `Microsoft-Windows-BackgroundTaskInfrastructure/Operational` event log and the host's execution.
  Neither `extendedBackgroundTaskTime` (declared) nor `AlwaysAllowed` background access (granted,
  with consent dialog) lifted it while the doorbell still flooded the prolog. Both were removed
  again afterwards and full-speed downloads succeeded — including with the app's background
  permission set to **DeniedByUser**, which is the strongest form of the test: vpnClient
  activations evidently bypass the user background-access policy entirely, so neither the
  capability nor any access level was ever part of the story. One durable side-fact: the
  `AlwaysAllowed` grant survives `Remove-AppxPackage` (stored against the app identity, not the
  package), unlike `broadFileSystemAccess`.
- **Why activations starved: `ProcessEventAsync` runs a delivery prolog first.** A mid-stall dump
  (taken by a log-tailing watcher 30 s before the execution, symbolized later) shows the
  89-second-old activation inside `VpnChannelFactory::ProcessEventAsync → VpnExeProcessTask →
  VpnExeHlpProcessProlog → VpnChannelImpl::CompleteDelivery → DatagramSocketServer::CompleteDelivery`
  — completing pending transport-datagram deliveries before its own event may run. Per-batch
  doorbell rings at line rate fed that prolog hundreds of datagrams a second; it never finished.
  Idle sessions drain it in seconds. The fix is the transition-ring protocol above; after it, the
  log shows scheduling activations completing every few seconds *during* a 165 Mbit/s download.
- **The platform keeps one rolling scheduling activation alive** — the next starts moments after
  the previous completes. `GetKeepAlivePayload` is *not* what completes them (never called, logged
  to prove it).
- **A cancelled activation should still yield**: `VpnBackgroundTask` registers `Canceled` and opens
  a 250 ms `ActivationYield` window; `Decapsulate` returns (ringing if work remains) and
  `Encapsulate` stops taking. This cannot save an activation stuck inside the platform's own
  prolog, but it makes legitimate cancels graceful.
- **Spent hosts no longer exist on the clean path.** The whole pathology — the connection-carrying
  activation parked forever in `VpnExeProcessTask → VpnExeWaitForTaskToIdle`, the +90 s cancel and
  host kill, the reconnect-into-a-condemned-host hazard (observed once: reconnect at +18 s, dead at
  +90 s) — was downstream of not calling `Stop` inside `Disconnect`. With the conforming disconnect
  (see the `Stop` bullet in the loopback-transport section) every activation completes and the host
  survives, unremarkable and reusable. `RetireHost` remains only on the failure paths — a failed
  connect, and the armor timeout around the in-callback `Stop` — where the platform-side state is
  wedged or unknown and a fresh host is the only safe successor. `Decapsulate` events are bounded
  (512 appends per call) for the same reason as the yield window — no single event may approach
  the watchdog.
- **Worker-thread injection without the doorbell does not work.** The M0'(5) probe
  (`RequestVpnPacketBuffer` + `AppendVpnReceivePacketBuffer` + `FlushVpnReceivePacketBuffers` from a
  worker) appends without error and the packet is never delivered — every probe line in every log
  lacks the echo that the doorbell path produces seconds earlier. The doorbell is load-bearing.
- **Forensics that worked**: activation start/completion logging with instance IDs (matches the ID
  in the cancel notification); a background watcher that tails `wsshvpn.log` and dumps the host
  when an activation is 55 s old and uncompleted; `.dump /ma` needs no symbols at capture time.
  **Symbols need the network, and the network is the tunnel**: during a stall no new connection
  opens, so `.reload` silently resolves nothing — fetch PDBs after reconnecting.
  `Windows.Networking.pdb` on the public server has private symbols; `Windows.Networking.Vpn.pdb`
  is public-only. Also mind that non-invasive attaches suspend the whole process: a debugger that
  then fetches symbols *through the suspended tunnel* deadlocks itself and kills the session — that
  is what once dropped the user's connection during sampling.

### Threads, and which of them may block

The stack is single-threaded **by contract, not by luck** — no flow locks any of its state, and each
`TcpFlow` writes into a scratch buffer it assumes it has to itself. Two threads in one flow produce a
corrupt packet rather than an exception, so the boundaries below are load-bearing:

| Thread | Owns | Must never |
|---|---|---|
| **T-Plat** (the platform's, inside `Encapsulate`/`Decapsulate`) | copy outbound packets and queue them; append queued buffers to `decapsulatedPackets` | call into SSH; block |
| **T-Listen** (SSH.NET's message listener) | copy inbound bytes into the per-flow buffer, set a readiness bit | wait on anything of ours; close or dispose a channel |
| **T-Stack** (`PacketPath`'s thread) | the flow table, every TCB, timers, segment building, `GetVpnReceivePacketBuffer`, ringing the doorbell | block on anything |

Every call into SSH.NET can block for up to 30 seconds — `Channel.SendData` waits on a window the
listener thread must deliver, and `SendMessage` waits during rekey. That is why opening a channel
happens on a worker, and why **the open's callback only queues**: `StackLoop` drains
`_arrivals` on T-Stack at the top of `RunOnce`. Anything else added to the seams must do the same.

Backpressure rather than blocking, in both directions: a full outbound queue drops (the OS
retransmits), and a full `IPacketSink` leaves received bytes unreleased, which closes the SSH
channel's window and slows the far end down.

### Throughput: what was measured, so nobody re-guesses it

The tunnel ran at 630 kbit/s and ended one long hunt at ~40-50 Mbit/s sustained. Every step was
measured, and most plausible theories were wrong; the order below is the order of *elimination*:

- **The SSH channel window** (8 KiB default) was the first, real ceiling: 8→128 KiB scaled
  throughput ~linearly to ~8 Mbit/s. Beyond that it was innocent — 2 MiB (OpenSSH's
  `CHAN_TCP_WINDOW_DEFAULT`) changed nothing and `window-full` stayed 0 at every rate. Windows now
  match OpenSSH anyway, made affordable by `DirectTcpipStream` growing its buffer on demand.
- **Not the platform sink** (stalls fell 7× with no gain; deepening the queue without the fairness
  quantum below *dropped 4566 outbound packets* and killed connections), **not the transport**
  (classic socket == WinRT socket, both ~8 Mbit), **not the environment** (a source-bound `ssh -D`
  on the same machine *with the VPN connected* did 282 Mbit/s — the decisive experiment),
  **not window credits** (measured flowing at consumption rate).
- **The real 8 Mbit ceiling: an RCW per packet.** Sampled live with `cdbX64 -pv` on the pegged
  stack thread: `CreateMemoryBufferOverIBuffer`+`CreateReference` per packet → each RCW creation ran
  `GetRuntimeClassName`, which **fails inside WinTypes and fires `RoOriginateError`**, whose report
  capture does registry I/O — ~1 ms/packet, one core caps at ~900 packets/s. Fix:
  `IBufferByteAccess` QI on the `IBuffer` already in hand (`VpnPacketBufferAccess.GetSpan`), zero
  new WinRT objects per packet. **Never create a WinRT object on the packet path.** 4-6× immediately.
- **At 30+ Mbit/s, injected-segment loss is real** and the two TCP-sender liberties stopped being
  survivable: the peer's advertised window is now honored, and channel bytes are released on the
  client's ACK rather than on send — the channel buffer *is* the retransmit buffer, with a 200 ms
  doubling RTO doing go-back-N (SYN and FIN occupy sequence numbers but no buffer, and are excluded
  from the release accounting).
- **The fairness quantum in `TcpFlow` (8 segments per flow per visit) is load-bearing**: without it
  the inbound queue capacity silently doubles as the inbound/outbound fairness bound.
- **The 8-slot blocking channel-open pool was the last measured killer of fast downloads**: slow
  opens held slots for the 30 s SSH timeout, refusals cascaded, and a browser retry storm followed
  (flows 30→63 with `Refusing a channel` flooding the log at the moment of death). Replaced by
  async opens: an open in flight is a `TaskCompletionSource`, a timed-out open (default 3 s,
  `<OpenTimeoutSeconds>`) is *abandoned* — never disposed, because before confirmation a dispose
  puts nothing on the wire and unsubscribes from a confirmation that may still arrive, leaking the
  channel server-side. The abandoned object holds a slot in `MaximumLiveChannels = 128`
  (opens in flight + open channels + abandoned-awaiting-answer) until the server answers.
- **After the opens were fixed, downloads still died — of data corruption, not congestion.** The
  post-mortem line (logged when a client resets a live flow) showed a *healthy* sender at the moment
  of death: data moving, window open, zero retransmissions — which for a TLS flow means exactly one
  thing, a failed record MAC. Cause: `DirectTcpipStream` compacted its receive buffer **in place on
  the listener thread**, an overlapping copy under the segment T-Stack was concurrently reading via
  `TryRead`. Release-on-ACK made it probable: the held region grew from near-nothing to megabytes,
  so every append compacted under a reader. Fix in the fork: the receive path only ever grows into a
  *fresh* array; reclaiming happens in `FlushWindowCredit` on the consumer's thread, where peeked
  segments are contractually dead — and crediting and reclaiming *must* move together, or the window
  outruns the tail space. Rule of thumb it establishes: **nothing may mutate, in place, an array a
  peeked segment points into.**
- **The remaining per-packet RCWs went the same way as the first one: raw ABI.** `VpnChannelAbi`
  carries hand-written function-pointer vtables, every IID and slot cited from the SDK's MIDL
  headers, and the inbound queue carries owned `IVpnPacketBuffer` pointers. Traps that survive only
  as those citations: `GetVpnReceivePacketBuffer` is `IVpnChannel2` slot 11 while `IVpnChannel`'s
  slot 11 is `LogDiagnosticMessage`, and `RemoveAtEnd` precedes `RemoveAtBegin` on the list.
  Measured immediately after: 67.7 Mbit/s peak, ~62 sustained, zero retransmissions — up from the
  51-peak/40-sustained of the projected path.
- **The last two rungs were the checksum and the doorbell.** `InternetChecksum.Accumulate` read one
  big-endian 16-bit word at a time (~680 reads/packet) — the stack thread's largest sampled cost —
  and now sums 64-bit chunks with end-around carry (RFC 1071 is congruent mod 2^16−1 at any word
  size; tests pin it to the definitional loop). `MonotonicClock.Now` stopped rounding through a
  double. The doorbell ring stopped being a WinRT stream-adapter write (an async-op RCW plus a
  reflected GUID per ring) and became one syscall on a classic UDP socket. With the activation
  watchdog also fixed: **165 Mbit/s peak, two full 6.1 GB downloads back to back** — the full arc
  from 630 kbit/s is ~260×.

### Open holes

Deliberate, documented, and not to be silently papered over:

- **Out-of-order segments are dropped**, and no SACK is offered — consistent, but it makes any real
  loss expensive.
- **IPv6 leaks.** An address is assigned (it must be, or `Start*` fails) but nothing is routed, so
  IPv6 keeps using the physical NIC. Accepted; routing it in with no stack behind it would black-hole
  it instead.
- **UDP other than DNS, and all ICMP, are dropped.** No SSH primitive carries either.
- The bring-up scaffolding is gone: `M0Spike` (`<SpikeProbe>`), `RemoteDummyTransport`,
  `<LargeFrameSize>` and the `<AssignIPv6>` switch were all removed once their questions were
  answered — the IPv6 address assignment is now unconditional, because there is no working value of
  "off". `<StartDelaySeconds>` stays; attaching a debugger to a per-activation host needs it.

### The fork's transport seam

The plug-in runs in an app container where the WinRT socket types are what is usable, so the fork
gained `Renci.SshNet.Connection.SshTransport` (public abstract: `Read`/`Write` plus async,
`IsConnected`, `Shutdown`, `Dispose`) and `ISshTransportFactory`, assigned via
`ConnectionInfo.TransportFactory`. Setting it replaces the built-in connectors entirely, proxy support
included. (The original reason — handing the platform the socket the session runs on — was disproved;
see the outer-transport section above.)

`StreamSocketSshTransportFactory` takes an optional `HostName` local address, threaded through to a
`ConnectAsync(EndpointPair)` with `LocalHostName` set. The local *service* name in that pair must be
the empty string; null is rejected.

`IConnector` and the five connectors deliberately still return `Socket` — `Session` wraps them in
`SocketSshTransport`. Pushing the abstraction down into the connector chain would churn ~100 test
files instead of 16; don't do it without a reason.

`StreamSocketSshTransport` lives in the fork too, built on `AsStreamForRead(0)` /
`AsStreamForWrite(0)` — unbuffered, since the session frames and buffers itself and a buffered
writer would sit on outgoing packets. Blocking on those tasks is safe only because no session thread
carries a synchronization context.

**The fork targets `net10.0-windows10.0.26100.0` only.** Upstream's five TFMs were collapsed to one
because `Windows.Networking.Sockets` is invisible from `net462`, `netstandard2.0` and plain
`net10.0` — that is what lets the WinRT transport live in the library instead of the plug-in. The
`#if NET` / `#if !NET` branches are now dead but were left in place to keep the diff against
upstream small. `RuntimeIdentifiers` is set because the plug-in publishes Native AOT per RID.

Do **not** set `UseUwp` on the fork. It authors no WinRT types, and turning it on enables CsWinRT's
authoring analyzers, which flag every class implementing `IDisposable` or holding a `WaitHandle`
(CsWinRT1028/CsWinRT1030) — dozens of warnings, and warnings are errors in Release.

Two teardown behaviours were established by test and are easy to get wrong again:

- `StreamSocket` has no half-close. `Shutdown()` uses `CancelIOAsync()`, which cancels only I/O
  **already in flight** — so `Read` must short-circuit to `0` once shutdown has run, or a read issued
  afterwards blocks forever.
- The WinRT stream adapter reports socket failures as `COMException`, not `IOException`. Teardown
  classification has to include it, and non-teardown failures are normalised to `IOException` so both
  transports present the same shape of error.

Those adapters live in `System.IO.WindowsRuntimeStreamExtensions`, and `AsBuffer`/`ToArray` in
`System.Runtime.InteropServices.WindowsRuntime` — both **are** available under CsWinRT UWP. They are
extension methods, so omitting the `using` yields CS1061, which reads exactly like the API having
been removed in .NET 5+. Import the namespace before concluding it's missing.

## Conventions

- `.editorconfig` sets `end_of_line = lf`, `charset = utf-8` and file-scoped namespaces. Nothing
  needs checking by hand: Roslyn reads BOM-less UTF-8 correctly (it tries UTF-8 first and only falls
  back to the ANSI codepage on invalid bytes), and git is not configured to normalise anything.
  Existing files predate this and are still CRLF with a BOM, which is simply what Visual Studio
  writes by default — so expect a mix until they are touched.
- The plug-in runs in the background task host with no debugger attached; `PluginLog` appends to
  `wsshvpn.log` in the package local folder. Prefer adding to that over `Debug.WriteLine` alone.
  **Log timestamps are UTC**; the app's status pane and the Windows event log are local time —
  correlate accordingly before concluding two events don't line up.
- Host keys are pinned from the profile, and an unpinned key is **refused** rather than trusted on
  first use — a background task has no UI to prompt from. Don't relax this to make testing easier.
- **This repo and the fork are public.** Machine-specific configuration (server address, user name,
  key path, LAN ranges, adapter names) lives in the app's local settings and the log, deliberately —
  keep it out of commits, including commit messages and comments quoting log lines.
- `dumps\` is gitignored and holds crash/hang dumps, log backups and the forensic watcher scripts.
  Dump analysis works offline: `cdbX64 -z <dump> -y "srv*<local symcache>*https://msdl.microsoft.com/download/symbols"`
  — capture needs no symbols, and PDBs fetched once are cached, which matters because a wedged
  tunnel blocks new connections including the symbol server's.
