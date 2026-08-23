using System;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// Writes the IP header of whichever family the addresses carry.
/// </summary>
/// <remarks>
/// The one place the emission paths branch on family, so the callers - segment building, resets, DNS
/// replies - stay written once.
/// </remarks>
internal static class IpHeader
{
    /// <summary>
    /// Writes an IP header for a payload already in place after it.
    /// </summary>
    /// <param name="buffer">The buffer to write into.</param>
    /// <param name="protocol">The protocol carried.</param>
    /// <param name="source">The source address.</param>
    /// <param name="destination">The destination address.</param>
    /// <param name="payloadLength">The length of the payload that follows the header.</param>
    /// <returns>The total length of the packet.</returns>
    public static int Write(
        Span<byte> buffer,
        IpProtocol protocol,
        in IpAddr source,
        in IpAddr destination,
        int payloadLength)
    {
        return source.IsV4
            ? Ipv4Packet.Write(buffer, protocol, source.V4, destination.V4, payloadLength)
            : Ipv6Packet.Write(buffer, protocol, source, destination, payloadLength);
    }
}
