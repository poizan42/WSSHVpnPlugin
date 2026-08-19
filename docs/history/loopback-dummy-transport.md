# The loopback-dummy outer transport (superseded 2026-08-18)

The architecture the plug-in shipped before the platform-owned transport: the platform was handed a
pair of cross-connected loopback `DatagramSocket`s that carried nothing, while SSH ran on a socket of
its own, bound to a chosen physical interface.

It is here rather than in `CLAUDE.md` because none of it describes the code any more. What replaced it
is **The platform-owned transport (the current architecture)** in `CLAUDE.md`, and the experiment that
built it is `docs\experiments\platform-owned-transport.md`. Kept because the reasoning is expensive to
rebuild and because knowing what was already tried is what stops it being tried again.

Three findings from this era outlived it and stayed in `CLAUDE.md`, so look for them there rather than
here: the doorbell injection protocol, the empty-to-non-empty ring rule, and the requirement to call
`channel.Stop()` inside the `Disconnect` callback. All three are architecture-independent and still
load-bearing.

## Why the platform cannot be given the SSH socket

The platform takes **exclusive ownership** of whatever is passed to `AssociateTransport`: it registers
the socket as a ControlChannelTrigger, then `Start*` calls `WaitForPushEnabled`,
`TakeTransportOwnership` and `VpnExeChannelCreate`, after which the VPN service reads and writes it
itself. An SSH session running over that socket has its bytes stolen — we watched the banner come back
corrupted. Established by crash dump, live stack and disassembly of `Windows.Networking.Vpn.dll`; do
not re-derive it.

So `LoopbackTransport` hands the platform a cross-connected pair of `DatagramSocket`s on `127.0.0.1`
that carries nothing, and SSH runs on a socket of its own.

## The choreography this needed

- **Order**: `AssociateTransport` first and on an *unconnected* socket, then bind both, then
  cross-connect, then `StartWithMainTransport` passing the same socket. Calling `Start*` on a channel
  that never had `AssociateTransport` dereferences NULL and kills the host; connecting before
  associating earns `E_OUTOFMEMORY` from the CCT broker, which is not about memory.
- **Datagrams, never a listener.** TCP cannot cross-connect, so a `StreamSocket` dummy would need a
  `StreamSocketListener` — the one loopback shape whose app-container behaviour is doubtful. Loopback
  itself needs no exemption: the check passes when both endpoints share the package SID.
- **SSH is source-bound** to a chosen interface (`OutboundInterface`), not kept out with
  `Ipv4ExclusionRoutes` (which returned `WSAEACCES` for that purpose in the reference implementation;
  ours is untested for it, and route-based exclusion does not work at all — see **Routing** in
  `CLAUDE.md`).
  `GetInternetConnectionProfile` is useless here —
  its "preferred interface" becomes the tunnel. The heuristic cannot tell our tunnel from another
  VPN's TAP adapter, so `<NetworkAdapter>` in the profile is a real requirement when nesting, not a
  nicety.
