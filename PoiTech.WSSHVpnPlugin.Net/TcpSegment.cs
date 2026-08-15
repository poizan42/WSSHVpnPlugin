using System;
using System.Buffers.Binary;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// Reads and writes TCP segments in place.
/// </summary>
internal readonly ref struct TcpSegment
{
    /// <summary>The smallest valid TCP header, with no options.</summary>
    public const int MinimumHeaderLength = 20;

    private readonly Span<byte> _segment;

    private TcpSegment(Span<byte> segment)
    {
        _segment = segment;
    }

    /// <summary>Gets the source port.</summary>
    public ushort SourcePort => BinaryPrimitives.ReadUInt16BigEndian(_segment[0..2]);

    /// <summary>Gets the destination port.</summary>
    public ushort DestinationPort => BinaryPrimitives.ReadUInt16BigEndian(_segment[2..4]);

    /// <summary>Gets the sequence number.</summary>
    public uint SequenceNumber => BinaryPrimitives.ReadUInt32BigEndian(_segment[4..8]);

    /// <summary>Gets the acknowledgement number.</summary>
    public uint AcknowledgementNumber => BinaryPrimitives.ReadUInt32BigEndian(_segment[8..12]);

    /// <summary>Gets the flags.</summary>
    public TcpFlags Flags => (TcpFlags)(_segment[13] & 0x3F);

    /// <summary>Gets the advertised receive window.</summary>
    public ushort WindowSize => BinaryPrimitives.ReadUInt16BigEndian(_segment[14..16]);

    /// <summary>Gets the length of the header, including any options.</summary>
    public int HeaderLength => (_segment[12] >> 4) * 4;

    /// <summary>Gets the segment's payload.</summary>
    public Span<byte> Payload => _segment[HeaderLength..];

    /// <summary>Gets the options, between the fixed header and the payload.</summary>
    public Span<byte> Options => _segment[MinimumHeaderLength..HeaderLength];

    /// <summary>
    /// Views a buffer as a TCP segment, if it plausibly is one.
    /// </summary>
    /// <param name="buffer">The buffer to view, exactly the length of the segment.</param>
    /// <param name="segment">The resulting view.</param>
    /// <returns>
    /// <see langword="true"/> if the buffer holds a self-consistent TCP header; otherwise,
    /// <see langword="false"/>.
    /// </returns>
    public static bool TryParse(Span<byte> buffer, out TcpSegment segment)
    {
        segment = default;

        if (buffer.Length < MinimumHeaderLength)
        {
            return false;
        }

        var headerLength = (buffer[12] >> 4) * 4;
        if (headerLength < MinimumHeaderLength || headerLength > buffer.Length)
        {
            return false;
        }

        segment = new TcpSegment(buffer);
        return true;
    }

    /// <summary>
    /// Reads the maximum segment size the peer advertised, if it advertised one.
    /// </summary>
    /// <param name="mss">Receives the advertised maximum segment size.</param>
    /// <returns>
    /// <see langword="true"/> if an MSS option was present and well-formed; otherwise,
    /// <see langword="false"/>.
    /// </returns>
    /// <remarks>
    /// A peer that sends no MSS option is assuming 536, which is the reason to always send one back:
    /// omitting it halves throughput while appearing to work.
    /// </remarks>
    public bool TryGetMaximumSegmentSize(out ushort mss)
    {
        mss = 0;

        var options = Options;
        var i = 0;

        while (i < options.Length)
        {
            var kind = options[i];

            if (kind == 0)
            {
                // End of option list.
                return false;
            }

            if (kind == 1)
            {
                // No-op padding, one byte with no length.
                i++;
                continue;
            }

            if (i + 1 >= options.Length)
            {
                return false;
            }

            var length = options[i + 1];
            if (length < 2 || i + length > options.Length)
            {
                return false;
            }

            if (kind == 2 && length == 4)
            {
                mss = BinaryPrimitives.ReadUInt16BigEndian(options.Slice(i + 2, 2));
                return true;
            }

            i += length;
        }

        return false;
    }

    /// <summary>
    /// Verifies the segment's checksum against the addresses that carried it.
    /// </summary>
    /// <param name="source">The source address of the packet.</param>
    /// <param name="destination">The destination address of the packet.</param>
    /// <returns>
    /// <see langword="true"/> if the checksum is correct or absent; otherwise, <see langword="false"/>.
    /// </returns>
    /// <remarks>
    /// A zero checksum is accepted. Nothing guarantees the platform hands us segments with valid
    /// checksums - if it treats the tunnel interface as offload-capable they may never be computed -
    /// and a stack that dropped those would blackhole every flow while looking healthy.
    /// </remarks>
    public bool IsChecksumValid(uint source, uint destination)
    {
        if (BinaryPrimitives.ReadUInt16BigEndian(_segment[16..18]) == 0)
        {
            return true;
        }

        return ComputeChecksum(_segment, source, destination) == 0;
    }

    /// <summary>
    /// Writes a TCP segment, with a correct checksum, for a payload already in place after the header.
    /// </summary>
    /// <param name="buffer">The buffer to write into, starting at the TCP header.</param>
    /// <param name="source">The source address, for the pseudo-header.</param>
    /// <param name="destination">The destination address, for the pseudo-header.</param>
    /// <param name="sourcePort">The source port.</param>
    /// <param name="destinationPort">The destination port.</param>
    /// <param name="sequenceNumber">The sequence number.</param>
    /// <param name="acknowledgementNumber">The acknowledgement number.</param>
    /// <param name="flags">The flags.</param>
    /// <param name="windowSize">The receive window to advertise.</param>
    /// <param name="payloadLength">The length of the payload that follows the header.</param>
    /// <param name="maximumSegmentSize">
    /// The maximum segment size to advertise, or <see langword="null"/> for no option. Only valid on
    /// a segment carrying SYN.
    /// </param>
    /// <returns>The total length of the segment.</returns>
    public static int Write(
        Span<byte> buffer,
        uint source,
        uint destination,
        ushort sourcePort,
        ushort destinationPort,
        uint sequenceNumber,
        uint acknowledgementNumber,
        TcpFlags flags,
        ushort windowSize,
        int payloadLength,
        ushort? maximumSegmentSize = null)
    {
        var headerLength = MinimumHeaderLength + (maximumSegmentSize.HasValue ? 4 : 0);
        var header = buffer[..headerLength];

        header.Clear();
        BinaryPrimitives.WriteUInt16BigEndian(header[0..2], sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..4], destinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(header[4..8], sequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(header[8..12], acknowledgementNumber);
        header[12] = (byte)((headerLength / 4) << 4);
        header[13] = (byte)flags;
        BinaryPrimitives.WriteUInt16BigEndian(header[14..16], windowSize);

        if (maximumSegmentSize.HasValue)
        {
            header[MinimumHeaderLength] = 2;      // kind: MSS
            header[MinimumHeaderLength + 1] = 4;  // length
            BinaryPrimitives.WriteUInt16BigEndian(header[(MinimumHeaderLength + 2)..headerLength], maximumSegmentSize.Value);
        }

        var total = headerLength + payloadLength;
        BinaryPrimitives.WriteUInt16BigEndian(
            header[16..18],
            ComputeChecksum(buffer[..total], source, destination));

        return total;
    }

    /// <summary>
    /// Computes the TCP checksum over the pseudo-header and the segment.
    /// </summary>
    private static ushort ComputeChecksum(ReadOnlySpan<byte> segment, uint source, uint destination)
    {
        Span<byte> pseudoHeader = stackalloc byte[12];
        BinaryPrimitives.WriteUInt32BigEndian(pseudoHeader[0..4], source);
        BinaryPrimitives.WriteUInt32BigEndian(pseudoHeader[4..8], destination);
        pseudoHeader[8] = 0;
        pseudoHeader[9] = (byte)IpProtocol.Tcp;
        BinaryPrimitives.WriteUInt16BigEndian(pseudoHeader[10..12], (ushort)segment.Length);

        var sum = InternetChecksum.Accumulate(0, pseudoHeader);
        sum = InternetChecksum.Accumulate(sum, segment);
        return InternetChecksum.Finish(sum);
    }
}
