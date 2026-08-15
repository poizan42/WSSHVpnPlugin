using System;
using System.Buffers.Binary;
using System.Net;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// Reads and writes IPv4 headers in place.
/// </summary>
/// <remarks>
/// A view over a caller's buffer rather than a parsed object: the packets come from and go back to
/// the VPN platform's own buffers, and copying each one into a header object and out again would
/// double the work on the busiest path in the program.
/// </remarks>
internal readonly ref struct Ipv4Packet
{
    /// <summary>The smallest valid IPv4 header, with no options.</summary>
    public const int MinimumHeaderLength = 20;

    private readonly Span<byte> _packet;

    private Ipv4Packet(Span<byte> packet)
    {
        _packet = packet;
    }

    /// <summary>Gets the protocol carried by this packet.</summary>
    public IpProtocol Protocol => (IpProtocol)_packet[9];

    /// <summary>Gets the source address.</summary>
    public uint Source => BinaryPrimitives.ReadUInt32BigEndian(_packet[12..16]);

    /// <summary>Gets the destination address.</summary>
    public uint Destination => BinaryPrimitives.ReadUInt32BigEndian(_packet[16..20]);

    /// <summary>Gets the length of the header, including any options.</summary>
    public int HeaderLength => (_packet[0] & 0x0F) * 4;

    /// <summary>Gets the total length of the packet as the header declares it.</summary>
    public int TotalLength => BinaryPrimitives.ReadUInt16BigEndian(_packet[2..4]);

    /// <summary>Gets the payload, after the header and clipped to the declared total length.</summary>
    public Span<byte> Payload => _packet[HeaderLength..TotalLength];

    /// <summary>Gets the whole packet.</summary>
    public Span<byte> Bytes => _packet[..TotalLength];

    /// <summary>
    /// Gets a value indicating whether this packet is fragmented.
    /// </summary>
    /// <value>
    /// <see langword="true"/> if the more-fragments flag is set or the fragment offset is non-zero;
    /// otherwise, <see langword="false"/>.
    /// </value>
    /// <remarks>
    /// Reassembly is not implemented. A tunnel that advertises its MTU should not see fragments, and
    /// silently treating a fragment as a whole packet would corrupt a flow rather than drop it.
    /// </remarks>
    public bool IsFragment
    {
        get
        {
            var flagsAndOffset = BinaryPrimitives.ReadUInt16BigEndian(_packet[6..8]);
            return (flagsAndOffset & 0x2000) != 0 || (flagsAndOffset & 0x1FFF) != 0;
        }
    }

    /// <summary>
    /// Views a buffer as an IPv4 packet, if it plausibly is one.
    /// </summary>
    /// <param name="buffer">The buffer to view.</param>
    /// <param name="packet">The resulting view.</param>
    /// <returns>
    /// <see langword="true"/> if the buffer holds a self-consistent IPv4 header; otherwise,
    /// <see langword="false"/>.
    /// </returns>
    /// <remarks>
    /// Every length is checked against the buffer before anything reads through it. The bytes come
    /// from another machine's stack by way of ours, and a header claiming more than it has is the
    /// cheapest way to read off the end of a buffer.
    /// </remarks>
    public static bool TryParse(Span<byte> buffer, out Ipv4Packet packet)
    {
        packet = default;

        if (buffer.Length < MinimumHeaderLength)
        {
            return false;
        }

        if ((buffer[0] >> 4) != 4)
        {
            return false;
        }

        var headerLength = (buffer[0] & 0x0F) * 4;
        if (headerLength < MinimumHeaderLength || headerLength > buffer.Length)
        {
            return false;
        }

        var totalLength = BinaryPrimitives.ReadUInt16BigEndian(buffer[2..4]);
        if (totalLength < headerLength || totalLength > buffer.Length)
        {
            return false;
        }

        packet = new Ipv4Packet(buffer);
        return true;
    }

    /// <summary>
    /// Writes an IPv4 header, with a correct checksum, for a payload already in place after it.
    /// </summary>
    /// <param name="buffer">The buffer to write into.</param>
    /// <param name="protocol">The protocol carried.</param>
    /// <param name="source">The source address.</param>
    /// <param name="destination">The destination address.</param>
    /// <param name="payloadLength">The length of the payload that follows the header.</param>
    /// <param name="identification">The identification field.</param>
    /// <returns>The total length of the packet.</returns>
    public static int Write(
        Span<byte> buffer,
        IpProtocol protocol,
        uint source,
        uint destination,
        int payloadLength,
        ushort identification = 0)
    {
        var total = MinimumHeaderLength + payloadLength;
        var header = buffer[..MinimumHeaderLength];

        header.Clear();
        header[0] = 0x45;                                                      // IPv4, 20-byte header
        BinaryPrimitives.WriteUInt16BigEndian(header[2..4], (ushort)total);
        BinaryPrimitives.WriteUInt16BigEndian(header[4..6], identification);
        BinaryPrimitives.WriteUInt16BigEndian(header[6..8], 0x4000);           // don't fragment
        header[8] = 64;                                                        // TTL
        header[9] = (byte)protocol;
        BinaryPrimitives.WriteUInt32BigEndian(header[12..16], source);
        BinaryPrimitives.WriteUInt32BigEndian(header[16..20], destination);
        BinaryPrimitives.WriteUInt16BigEndian(header[10..12], InternetChecksum.Compute(header));

        return total;
    }

    /// <summary>
    /// Formats an address for logging.
    /// </summary>
    /// <param name="address">The address, in host byte order.</param>
    /// <returns>The dotted-quad form.</returns>
    public static string Format(uint address)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, address);
        return new IPAddress(bytes).ToString();
    }
}
