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

## Tests

This repo has none. The `SSH.NET` submodule has its own suite; fork changes should be validated there:

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

Three projects plus the fork:

- **`PoiTech.WSSHVpnPlugin.VpnPlugin`** — the plug-in. A CsWinRT component (`CsWinRTComponent`),
  so **public types must be WinRT-compatible**; keep everything except `SSHVpnPlugin` and
  `VpnBackgroundTask` `internal`.
- **`PoiTech.WSSHVpnPlugin.App`** — UWP XAML app whose only real job is creating the VPN profile via
  `VpnManagementAgent`. There is no system UI for provisioning a plug-in profile, so this is the only
  way one gets created.
- **`PoiTech.WSSHVpnPlugin.Package`** — wapproj; owns `Package.appxmanifest`.
- **`SSH.NET`** — submodule, fork of upstream. It exists because
  `Session.CreateChannelDirectTcpip`, `ISession`, and `IChannelDirectTcpip` are all `internal`
  upstream.

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
   into the component assembly, but Native AOT links the component into the app's single executable,
   so `PoiTech.WSSHVpnPlugin.App.csproj` carries `UnmanagedEntryPointsAssembly` +
   `<LinkerArg Include="/EXPORT:DllGetActivationFactory" />` to keep and re-export it. Verify with
   `dumpbin /exports` on the published exe if activation ever stops working.

Paths in the manifest are `PoiTech.WSSHVpnPlugin.App\PoiTech.WSSHVpnPlugin.App.exe` — the wapproj
nests the app's payload in a subfolder, and `$targetnametoken$` resolves to the *wapproj* name here,
not the app's, so it can't be used.

The app project also needs a `Microsoft.Windows.CsWinRT` PackageReference despite authoring no WinRT
types: its targets are what strip the referenced component's `.winmd` out of compile references
(otherwise `NETSDK1130`).

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
  and succeed identically.
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
- UDP and ICMP need a separate answer; plain SSH has no primitive for either.

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
  `Decapsulate` only appends, which is what returns the buffer. One copy, not two. Ring the doorbell
  **per batch, unconditionally** — transition-only ringing stalls forever if a single ring is lost.
- **`Disconnect` must not call `channel.Stop()`.** Buffers we have not returned block the background
  task and the platform kills the host process. Close the queue, ring once more, and let `Decapsulate`
  stop the channel when it finds the queue drained. Whether that last call actually arrives is
  unresolved — `SSHVpnPlugin.OnStopWatchdog` reports which way it went.
- **Never a literal `0.0.0.0/0` inclusion route** — recorded in the reference implementation as looping
  back through the tunnel even from a bound socket. Use `0.0.0.0/1` + `128.0.0.0/1`. And only add
  routes for a family that has an assigned address, or the platform hangs.
- **SSH is source-bound** to a chosen interface (`OutboundInterface`), not kept out with
  `Ipv4ExclusionRoutes` (which returns `WSAEACCES`). `GetInternetConnectionProfile` is useless here —
  its "preferred interface" becomes the tunnel. The heuristic cannot tell our tunnel from another
  VPN's TAP adapter, so `<NetworkAdapter>` in the profile is a real requirement when nesting, not a
  nicety.

### Open holes

Deliberate, documented, and not to be silently papered over:

- `SshVpnConnection.SendOutbound` is where the user-space TCP/IP stack goes.
- `IChannelDirectTcpip` is still `internal`, and its `Open` binds a channel to a `Socket` rather than
  exposing a byte stream, so the fork needs a visibility *and* an API change before the packet path
  can use it.

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

- **CRLF and a UTF-8 BOM** on `.cs`, `.xaml`, and `.appxmanifest`. There is no `.gitattributes`, so
  writing LF or dropping the BOM turns an edit into a whole-file rewrite in the diff. Check before
  committing.
- File-scoped namespaces (`.editorconfig`).
- The plug-in runs in the background task host with no debugger attached; `PluginLog` appends to
  `wsshvpn.log` in the package local folder. Prefer adding to that over `Debug.WriteLine` alone.
- Host keys are pinned from the profile, and an unpinned key is **refused** rather than trusted on
  first use — a background task has no UI to prompt from. Don't relax this to make testing easier.
