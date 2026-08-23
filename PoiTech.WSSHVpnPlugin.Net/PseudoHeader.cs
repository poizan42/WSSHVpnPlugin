using System;
using System.Buffers.Binary;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// Accumulates the checksum pseudo-header for whichever family the addresses carry.
/// </summary>
/// <remarks>
/// The two layouts share nothing but intent: IPv4's is 12 bytes with a 16-bit length, IPv6's is 40
/// bytes with a 32-bit length and the next-header value in the last byte (RFC 8200 §8.1). The 32-bit
/// length is the trap - reusing the 16-bit slot silently computes a wrong checksum for every v6
/// segment.
/// </remarks>
internal static class PseudoHeader
{
    /// <summary>
    /// Starts a checksum with the pseudo-header for a transport payload of the given length.
    /// </summary>
    /// <param name="source">The source address.</param>
    /// <param name="destination">The destination address.</param>
    /// <param name="protocol">The transport protocol.</param>
    /// <param name="upperLayerLength">The transport header plus payload length.</param>
    /// <returns>The running sum, to be continued over the transport bytes.</returns>
    public static uint Accumulate(in IpAddr source, in IpAddr destination, IpProtocol protocol, int upperLayerLength)
    {
        if (source.IsV4)
        {
            Span<byte> pseudoHeader = stackalloc byte[12];
            BinaryPrimitives.WriteUInt32BigEndian(pseudoHeader[0..4], source.V4);
            BinaryPrimitives.WriteUInt32BigEndian(pseudoHeader[4..8], destination.V4);
            pseudoHeader[8] = 0;
            pseudoHeader[9] = (byte)protocol;
            BinaryPrimitives.WriteUInt16BigEndian(pseudoHeader[10..12], (ushort)upperLayerLength);
            return InternetChecksum.Accumulate(0, pseudoHeader);
        }

        Span<byte> pseudoHeader6 = stackalloc byte[40];
        pseudoHeader6.Clear();
        source.WriteV6(pseudoHeader6[0..16]);
        destination.WriteV6(pseudoHeader6[16..32]);
        BinaryPrimitives.WriteUInt32BigEndian(pseudoHeader6[32..36], (uint)upperLayerLength);
        pseudoHeader6[39] = (byte)protocol;
        return InternetChecksum.Accumulate(0, pseudoHeader6);
    }
}
