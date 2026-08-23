namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// Identifies a TCP flow by its four-tuple.
/// </summary>
/// <remarks>
/// Both addresses are always the same family: they come from one packet's header.
/// </remarks>
/// <param name="LocalAddress">The address of the machine inside the tunnel.</param>
/// <param name="LocalPort">The port of the machine inside the tunnel.</param>
/// <param name="RemoteAddress">The address being connected to.</param>
/// <param name="RemotePort">The port being connected to.</param>
internal readonly record struct TcpFlowKey(IpAddr LocalAddress, ushort LocalPort, IpAddr RemoteAddress, ushort RemotePort);
