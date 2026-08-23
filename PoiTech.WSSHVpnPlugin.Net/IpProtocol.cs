namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// The IP protocol numbers this stack cares about, including the IPv6 next-header values it
/// recognises only to drop.
/// </summary>
internal enum IpProtocol : byte
{
    /// <summary>IPv6 hop-by-hop options extension header.</summary>
    HopByHopOptions = 0,

    /// <summary>Internet Control Message Protocol.</summary>
    Icmp = 1,

    /// <summary>Internet Group Management Protocol.</summary>
    Igmp = 2,

    /// <summary>Transmission Control Protocol.</summary>
    Tcp = 6,

    /// <summary>User Datagram Protocol.</summary>
    Udp = 17,

    /// <summary>IPv6 fragment extension header.</summary>
    Fragment = 44,

    /// <summary>Internet Control Message Protocol for IPv6.</summary>
    IcmpV6 = 58,
}
