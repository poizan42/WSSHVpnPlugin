namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// Identifies a TCP flow by its four-tuple.
/// </summary>
/// <param name="LocalAddress">The address of the machine inside the tunnel.</param>
/// <param name="LocalPort">The port of the machine inside the tunnel.</param>
/// <param name="RemoteAddress">The address being connected to.</param>
/// <param name="RemotePort">The port being connected to.</param>
internal readonly record struct TcpFlowKey(uint LocalAddress, ushort LocalPort, uint RemoteAddress, ushort RemotePort);
