# WSSHVpnPlugin

A Windows `IVpnPlugIn` provider that carries VPN traffic over an SSH connection.

## Layout

| Project | What it is |
| --- | --- |
| `PoiTech.WSSHVpnPlugin.Net` | The user-space TCP/IP stack: flow table, TCP state machine, and the DNS-over-TCP relay. Plain `net10.0` with no WinRT and no SSH — it reaches both through interfaces — so it runs on synthetic packets with no session and no threads. |
| `PoiTech.WSSHVpnPlugin.Net.Tests` | MSTest against that stack. The only fast loop here: no deploy, under a second. |
| `PoiTech.WSSHVpnPlugin.VpnPlugin` | The plug-in itself: a CsWinRT WinRT component holding `VpnBackgroundTask` (the class the platform activates) and `SSHVpnPlugin` (the `IVpnPlugIn` implementation). Also where WinRT and SSH are wired to the stack's interfaces, in `PacketPathAdapters.cs`. |
| `PoiTech.WSSHVpnPlugin.App` | UWP XAML app. Its only job is to create the VPN profile through `VpnManagementAgent` — there is no system UI for provisioning a plug-in profile. |
| `PoiTech.WSSHVpnPlugin.Package` | MSIX packaging project. Owns `Package.appxmanifest`. |
| `SSH.NET` | Submodule; a fork of SSH.NET, because upstream keeps `Session.CreateChannelDirectTcpip` internal. |

## Building

The UWP XAML compiler targets only run under Visual Studio's MSBuild, so `dotnet build` fails on
the app and packaging projects with "Program does not contain a static 'Main' method". Build from a
Developer Command Prompt (which puts both `MSBuild.exe` and `vswhere.exe` on `PATH` — the Native AOT
link step shells out to the latter):

```bash
MSBuild.exe PoiTech.WSSHVpnPlugin.Package\PoiTech.WSSHVpnPlugin.Package.wapproj /p:Platform=x64 /p:Configuration=Release /restore
```

`dotnet build` is fine for `PoiTech.WSSHVpnPlugin.VpnPlugin` on its own.

Build Release unless you specifically need a debug build, and never benchmark a Debug one: because
this publishes Native AOT, `Configuration=Debug` compiles the native code with ILC optimizations
disabled — worth roughly half the tunnel's throughput. Details in
[`docs/profiling/2026-08-19-release-build.md`](docs/profiling/2026-08-19-release-build.md).

## Running it locally

Developer Mode is enough; no signing needed. Register the loose layout the packaging build
produces — restricted capabilities are accepted on this path:

```bash
Add-AppxPackage -Register PoiTech.WSSHVpnPlugin.Package\bin\x64\Release\AppxManifest.xml
```

Switching configuration needs a `Remove-AppxPackage` first: registering a different configuration's
manifest over an existing registration reports success and silently keeps the old one, because the
identity and version are unchanged. Check `(Get-AppxPackage *3703e6b2*).InstallLocation`.

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
3. `<Path>` in that registration points at the plug-in's own native executable, which must export
   `DllGetActivationFactory`. CsWinRT's source generator emits one in the component assembly, and
   the plug-in project carries `UnmanagedEntryPointsAssembly` and `/EXPORT:DllGetActivationFactory`
   to keep Native AOT from trimming it and to export it.

The plug-in is deliberately its own executable and process, separate from the XAML app: hosting the
tunnel inside a XAML application's process meant PLM's suspend path ran `GC.Collect()` in the VPN
host, which deadlocked it and got it killed as hung 45–75 seconds after every connect. The host's
`Main` is `CoreApplication.RunWithActivationFactories(...)` — what `Application.Start` does, minus
XAML — and the app project must not reference the plug-in project.

`networkingVpnProvider` is a restricted capability: fine for sideloading, needs Microsoft approval
for Store submission.

## The packet path

SSH forwards byte streams, not IP datagrams, so there is no packet-for-packet encapsulation and the
usual `Encapsulate` / `Decapsulate` symmetry does not apply. `Encapsulate` consumes IP packets and
returns nothing — the SSH session owns the wire — while a user-space TCP/IP stack terminates each TCP
flow locally, carries it over its own `direct-tcpip` channel, and synthesises the return packets.
Those go back through `Decapsulate`, which the platform raises when a byte is written to a loopback
socket used as a doorbell.

DNS is the one exception to "TCP only", and not an optional one: assigning DNS servers pins the whole
machine's name resolution to the tunnel the moment it starts, so UDP/53 going nowhere would break
every name on the system rather than degrading. Each query is relayed over its own channel using the
two-byte length framing of RFC 7766 and turned back into a datagram; a reply too large for one
datagram comes back truncated, which makes the client retry over TCP. Other UDP and all ICMP are
dropped.

## Testing

The stack is where the logic lives and it needs neither a package build nor a VPN activation:

```bash
dotnet test PoiTech.WSSHVpnPlugin.Net.Tests\PoiTech.WSSHVpnPlugin.Net.Tests.csproj
```

Anything reproducible from a packet belongs there rather than in a deploy — the plug-in half costs a
build, a registration and an activation per attempt.

## The transport abstraction in the fork

The plug-in runs in an app container, where the WinRT socket types are what is usable. SSH.NET drove
a `System.Net.Sockets.Socket`, so the fork gained a seam:

(The original reason was different and turned out to be wrong: the session was going to run on the
very socket handed to `AssociateTransport`, so that the platform would recognise it and keep it out
of the tunnel. The platform takes exclusive ownership of that socket and reads it itself — we watched
the SSH banner come back corrupted — so the session now runs on a socket of its own and the platform
gets a loopback dummy. The seam is still needed, for the app-container reason above.)

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
