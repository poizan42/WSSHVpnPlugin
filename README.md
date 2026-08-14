# WSSHVpnPlugin

A Windows `IVpnPlugIn` provider that carries VPN traffic over an SSH connection.

## Layout

| Project | What it is |
| --- | --- |
| `PoiTech.WSSHVpnPlugin.VpnPlugin` | The plug-in itself: a CsWinRT WinRT component holding `VpnBackgroundTask` (the class the platform activates) and `SSHVpnPlugin` (the `IVpnPlugIn` implementation). |
| `PoiTech.WSSHVpnPlugin.App` | UWP XAML app. Its only job is to create the VPN profile through `VpnManagementAgent` — there is no system UI for provisioning a plug-in profile. |
| `PoiTech.WSSHVpnPlugin.Package` | MSIX packaging project. Owns `Package.appxmanifest`. |
| `SSH.NET` | Submodule; a fork of SSH.NET, because upstream keeps `Session.CreateChannelDirectTcpip` internal. |

## Building

The UWP XAML compiler targets only run under Visual Studio's MSBuild, so `dotnet build` fails on
the app and packaging projects with "Program does not contain a static 'Main' method". Build from a
Developer Command Prompt (which puts both `MSBuild.exe` and `vswhere.exe` on `PATH` — the Native AOT
link step shells out to the latter):

```bash
MSBuild.exe PoiTech.WSSHVpnPlugin.Package\PoiTech.WSSHVpnPlugin.Package.wapproj /p:Platform=x64 /p:Configuration=Debug /restore
```

`dotnet build` is fine for `PoiTech.WSSHVpnPlugin.VpnPlugin` on its own.

## Running it locally

Developer Mode is enough; no signing needed. Register the loose layout the packaging build
produces — restricted capabilities are accepted on this path:

```bash
Add-AppxPackage -Register PoiTech.WSSHVpnPlugin.Package\bin\x64\Debug\AppxManifest.xml
```

```bash
Get-AppxPackage *3703e6b2-f1f9-447d-b506-da47be3094ff* | Remove-AppxPackage
```

`AppxPackageSigningEnabled` is `false`, so the produced `.msix` is unsigned and has to be signed
before it can be installed the normal way. For that, the signing certificate's subject has to match
`Identity/@Publisher` exactly.

## How activation is wired up

Three pieces have to agree, and each was a separate build failure to get there:

1. `Package.appxmanifest` declares a second `<Application Id="Plugin">` whose
   `windows.backgroundTasks` extension has `<uap:Task Type="vpnClient" />`. There is no
   `windows.vpnPlugin` extension category — a VPN plug-in is a background task.
2. The same manifest declares a package-level `windows.activatableClass.inProcessServer` naming
   `VpnBackgroundTask`. Packaging fails without it ("not allowed to have EntryPoint=... without
   ActivatableClassId").
3. `<Path>` in that registration points at the app's native executable, which must export
   `DllGetActivationFactory`. CsWinRT's source generator emits one in the component assembly, but
   Native AOT links the component into the app's exe, so the app project carries
   `UnmanagedEntryPointsAssembly` and `/EXPORT:DllGetActivationFactory` to keep and re-export it.

`networkingVpnProvider` is a restricted capability: fine for sideloading, needs Microsoft approval
for Store submission.

## Open design questions

**Packet path.** SSH forwards byte streams, not IP datagrams, so there is no packet-for-packet
encapsulation. `Encapsulate` has to feed a user-space TCP/IP stack that maps each TCP flow onto a
`direct-tcpip` channel and synthesises the return packets, injecting them with
`RequestVpnPacketBuffer` / `AppendVpnReceivePacketBuffer`. UDP and ICMP need a separate answer.

**Fork surface — channels.** `ISession`, `IChannelDirectTcpip` and `ChannelDirectTcpip` are still
`internal`, and `IChannelDirectTcpip.Open` binds the channel to a `Socket` rather than exposing a
byte stream — so the fork still needs both a visibility change and a socket-free way to open and
pump a channel. This is the remaining reason the fork exists.

## The transport abstraction in the fork

`VpnChannel.StartWithMainTransport` will only accept a WinRT socket, because the platform has to
recognise the SSH connection to keep it out of the tunnel it installs. SSH.NET drove a
`System.Net.Sockets.Socket`, so the fork gained a seam:

- `Renci.SshNet.Connection.SshTransport` — public abstract byte pipe (`Read`/`Write` plus async,
  `IsConnected`, `Shutdown`, `Dispose`).
- `ISshTransportFactory`, assigned to `ConnectionInfo.TransportFactory`. When set, it replaces the
  built-in connectors entirely — and with them proxy support.
- `SocketSshTransport` wraps the ordinary socket, so the default path is unchanged.
- `StreamSocketSshTransport` runs the session over the WinRT socket, adapting it with
  `AsStreamForRead(0)` / `AsStreamForWrite(0)`. Unbuffered on both sides: the session does its own
  framing and buffering, and a buffered writer would sit on outgoing SSH packets instead of sending
  them.

`IConnector` and the five connectors still return `Socket`; `Session` wraps whatever they hand back.
That was deliberate — routing the abstraction through the connector chain would have churned about
a hundred test files instead of sixteen.

Because the fork exists only to serve this plug-in, its five target frameworks were collapsed to
`net10.0-windows10.0.26100.0`. That is what allows the WinRT transport to live in the library:
`Windows.Networking.Sockets` is not visible from `net462`, `netstandard2.0` or a plain `net10.0`.

## Diagnostics

The plug-in runs in the background task host with no debugger attached most of the time. It appends
to `wsshvpn.log` in the package's local folder (`PluginLog.LogPath`).
