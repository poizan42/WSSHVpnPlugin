using System;
using System.Buffers.Binary;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// Reads and writes UDP datagrams in place.
/// </summary>
internal readonly ref struct UdpDatagram
{
    /// <summary>The UDP header length, which is fixed.</summary>
    public const int HeaderLength = 8;

    private readonly Span<byte> _datagram;

    private UdpDatagram(Span<byte> datagram)
    {
        _datagram = datagram;
    }

    /// <summary>Gets the source port.</summary>
    public ushort SourcePort => BinaryPrimitives.ReadUInt16BigEndian(_datagram[0..2]);

    /// <summary>Gets the destination port.</summary>
    public ushort DestinationPort => BinaryPrimitives.ReadUInt16BigEndian(_datagram[2..4]);

    /// <summary>Gets the payload, clipped to the length the header declares.</summary>
    public Span<byte> Payload =>
        _datagram[HeaderLength..BinaryPrimitives.ReadUInt16BigEndian(_datagram[4..6])];

    /// <summary>
    /// Views a buffer as a UDP datagram, if it plausibly is one.
    /// </summary>
    /// <param name="buffer">The buffer to view, exactly the length of the datagram.</param>
    /// <param name="datagram">The resulting view.</param>
    /// <returns>
    /// <see langword="true"/> if the buffer holds a self-consistent UDP header; otherwise,
    /// <see langword="false"/>.
    /// </returns>
    public static bool TryParse(Span<byte> buffer, out UdpDatagram datagram)
    {
        datagram = default;

        if (buffer.Length < HeaderLength)
        {
            return false;
        }

        var length = BinaryPrimitives.ReadUInt16BigEndian(buffer[4..6]);
        if (length < HeaderLength || length > buffer.Length)
        {
            return false;
        }

        datagram = new UdpDatagram(buffer);
        return true;
    }

    /// <summary>
    /// Writes a UDP header, with a correct checksum, for a payload already in place after it.
    /// </summary>
    /// <param name="buffer">The buffer to write into, starting at the UDP header.</param>
    /// <param name="source">The source address, for the pseudo-header.</param>
    /// <param name="destination">The destination address, for the pseudo-header.</param>
    /// <param name="sourcePort">The source port.</param>
    /// <param name="destinationPort">The destination port.</param>
    /// <param name="payloadLength">The length of the payload that follows the header.</param>
    /// <returns>The total length of the datagram.</returns>
    public static int Write(
        Span<byte> buffer,
        in IpAddr source,
        in IpAddr destination,
        ushort sourcePort,
        ushort destinationPort,
        int payloadLength)
    {
        var total = HeaderLength + payloadLength;
        var header = buffer[..HeaderLength];

        BinaryPrimitives.WriteUInt16BigEndian(header[0..2], sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..4], destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(header[4..6], (ushort)total);
        BinaryPrimitives.WriteUInt16BigEndian(header[6..8], 0);

        var sum = PseudoHeader.Accumulate(source, destination, IpProtocol.Udp, total);
        sum = InternetChecksum.Accumulate(sum, buffer[..total]);
        var checksum = InternetChecksum.Finish(sum);

        // A computed checksum of zero is transmitted as all ones. Zero is the reserved value meaning
        // "not computed", and sending it would tell the receiver to skip the check we just did.
        BinaryPrimitives.WriteUInt16BigEndian(header[6..8], checksum == 0 ? (ushort)0xFFFF : checksum);

        return total;
    }
}
