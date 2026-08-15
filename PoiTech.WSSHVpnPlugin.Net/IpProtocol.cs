namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// The IP protocol numbers this stack cares about.
/// </summary>
internal enum IpProtocol : byte
{
    /// <summary>Internet Control Message Protocol.</summary>
    Icmp = 1,

    /// <summary>Internet Group Management Protocol.</summary>
    Igmp = 2,

    /// <summary>Transmission Control Protocol.</summary>
    Tcp = 6,

    /// <summary>User Datagram Protocol.</summary>
    Udp = 17,
}
