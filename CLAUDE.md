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
dotnet test SSH.NET\test\Renci.SshNet.Tests\Renci.SshNet.Tests.csproj -f net10.0
dotnet test SSH.NET\test\Renci.SshNet.Tests\Renci.SshNet.Tests.csproj -f net10.0 --filter FullyQualifiedName~ChannelDirectTcpip
```

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

### The central design constraint

SSH cannot carry raw IP datagrams. Its forwarding primitive (`direct-tcpip`) is a byte stream to a
host and port, so there is no packet-for-packet encapsulation and the usual `Encapsulate` /
`Decapsulate` symmetry does not apply:

- `Encapsulate` consumes IP packets and returns **nothing** — the SSH session owns the wire, not the
  platform. A user-space TCP/IP stack has to demultiplex flows onto `direct-tcpip` channels.
- `Decapsulate` stays unused; inbound packets get injected from the SSH receive loop via
  `RequestVpnPacketBuffer` / `AppendVpnReceivePacketBuffer` instead.
- UDP and ICMP need a separate answer; plain SSH has no primitive for either.

### Open holes

Deliberate, documented, and not to be silently papered over:

- `SshVpnConnection.OuterTunnelTransport` throws. `VpnChannel.StartWithMainTransport` wants a WinRT
  `StreamSocket` so the platform can keep the SSH connection out of the tunnel it installs; SSH.NET
  drives a `System.Net.Sockets.Socket`. Either the fork runs its transport over a `StreamSocket`, or
  the server address gets an explicit exclusion route instead.
- `SshVpnConnection.SendOutbound` is where the user-space TCP/IP stack goes.
- Nothing has been changed in the submodule yet. Beyond visibility, `IChannelDirectTcpip.Open` binds
  a channel to a `Socket` rather than exposing a byte stream, so the fork needs an API change too.

## Conventions

- **CRLF and a UTF-8 BOM** on `.cs`, `.xaml`, and `.appxmanifest`. There is no `.gitattributes`, so
  writing LF or dropping the BOM turns an edit into a whole-file rewrite in the diff. Check before
  committing.
- File-scoped namespaces (`.editorconfig`).
- The plug-in runs in the background task host with no debugger attached; `PluginLog` appends to
  `wsshvpn.log` in the package local folder. Prefer adding to that over `Debug.WriteLine` alone.
- Host keys are pinned from the profile, and an unpinned key is **refused** rather than trusted on
  first use — a background task has no UI to prompt from. Don't relax this to make testing easier.
