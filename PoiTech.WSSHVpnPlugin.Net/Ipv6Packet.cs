using System;
using System.Buffers.Binary;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// Reads and writes IPv6 headers in place.
/// </summary>
/// <remarks>
/// <para>
/// A view over a caller's buffer, for the same reason as <see cref="Ipv4Packet"/>: the packets come
/// from and go back to the VPN platform's own buffers.
/// </para>
/// <para>
/// Only the fixed 40-byte header is understood. Extension headers are not walked:
/// <see cref="Payload"/> is whatever <see cref="NextHeader"/> says follows the fixed header, and the
/// demultiplexer accepts only packets whose next header is directly a transport it carries. Traffic
/// a host originates puts TCP and UDP straight after the fixed header, so the walk would run zero
/// times on everything this stack serves.
/// </para>
/// </remarks>
internal readonly ref struct Ipv6Packet
{
    /// <summary>The IPv6 header length, which is fixed; extensions are the payload's problem.</summary>
    public const int HeaderLength = 40;

    private readonly Span<byte> _packet;

    private Ipv6Packet(Span<byte> packet)
    {
        _packet = packet;
    }

    /// <summary>Gets the next header: the protocol carried, or an extension header this stack drops.</summary>
    public IpProtocol NextHeader => (IpProtocol)_packet[6];

    /// <summary>Gets the source address.</summary>
    public IpAddr Source => IpAddr.ReadV6(_packet[8..24]);

    /// <summary>Gets the destination address.</summary>
    public IpAddr Destination => IpAddr.ReadV6(_packet[24..40]);

    /// <summary>Gets the payload length the header declares, which excludes the header itself.</summary>
    public int PayloadLength => BinaryPrimitives.ReadUInt16BigEndian(_packet[4..6]);

    /// <summary>Gets the total length of the packet.</summary>
    public int TotalLength => HeaderLength + PayloadLength;

    /// <summary>Gets the payload, after the fixed header and clipped to the declared length.</summary>
    public Span<byte> Payload => _packet[HeaderLength..TotalLength];

    /// <summary>Gets the whole packet.</summary>
    public Span<byte> Bytes => _packet[..TotalLength];

    /// <summary>
    /// Views a buffer as an IPv6 packet, if it plausibly is one.
    /// </summary>
    /// <param name="buffer">The buffer to view.</param>
    /// <param name="packet">The resulting view.</param>
    /// <returns>
    /// <see langword="true"/> if the buffer holds a self-consistent IPv6 header; otherwise,
    /// <see langword="false"/>.
    /// </returns>
    /// <remarks>
    /// The declared payload length is checked against the buffer before anything reads through it,
    /// for the same reason <see cref="Ipv4Packet.TryParse"/> checks its lengths.
    /// </remarks>
    public static bool TryParse(Span<byte> buffer, out Ipv6Packet packet)
    {
        packet = default;

        if (buffer.Length < HeaderLength)
        {
            return false;
        }

        if ((buffer[0] >> 4) != 6)
        {
            return false;
        }

        var totalLength = HeaderLength + BinaryPrimitives.ReadUInt16BigEndian(buffer[4..6]);
        if (totalLength > buffer.Length)
        {
            return false;
        }

        packet = new Ipv6Packet(buffer);
        return true;
    }

    /// <summary>
    /// Writes an IPv6 header for a payload already in place after it.
    /// </summary>
    /// <param name="buffer">The buffer to write into.</param>
    /// <param name="nextHeader">The protocol carried.</param>
    /// <param name="source">The source address.</param>
    /// <param name="destination">The destination address.</param>
    /// <param name="payloadLength">The length of the payload that follows the header.</param>
    /// <returns>The total length of the packet.</returns>
    /// <remarks>
    /// There is no header checksum to compute - IPv6 removed it, leaving integrity to the transport's
    /// pseudo-header checksum, which is why that one is mandatory.
    /// </remarks>
    public static int Write(
        Span<byte> buffer,
        IpProtocol nextHeader,
        in IpAddr source,
        in IpAddr destination,
        int payloadLength)
    {
        var header = buffer[..HeaderLength];

        header.Clear();
        header[0] = 0x60;                                                          // IPv6, no traffic class
        BinaryPrimitives.WriteUInt16BigEndian(header[4..6], (ushort)payloadLength);
        header[6] = (byte)nextHeader;
        header[7] = 64;                                                            // hop limit
        source.WriteV6(header[8..24]);
        destination.WriteV6(header[24..40]);

        return HeaderLength + payloadLength;
    }
}
