using System;
using System.Buffers.Binary;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// Just enough of a DNS message to answer a query we cannot deliver whole.
/// </summary>
/// <remarks>
/// Deliberately not a parser. Queries are relayed verbatim and replies are returned verbatim; the
/// only thing this stack ever has to understand is how much of a reply the client is willing to
/// receive, and how to say "ask again over TCP" when the reply is larger than that.
/// </remarks>
internal static class DnsMessage
{
    /// <summary>The fixed header: identifier, flags, and the four section counts.</summary>
    public const int HeaderLength = 12;

    /// <summary>The most a client may be assumed to accept without saying so.</summary>
    /// <remarks>RFC 1035's limit, and still the right assumption for a client that sends no OPT.</remarks>
    public const int ClassicMaximumSize = 512;

    /// <summary>The resource record type of an EDNS0 OPT pseudo-record.</summary>
    private const ushort OptRecordType = 41;

    /// <summary>
    /// Reads how large a reply the client said it would accept.
    /// </summary>
    /// <param name="query">The query message.</param>
    /// <returns>
    /// The advertised payload size, floored at <see cref="ClassicMaximumSize"/>, or that value if the
    /// query carries no EDNS0 OPT record or cannot be walked.
    /// </returns>
    /// <remarks>
    /// EDNS0 puts the size in the OPT record's class field, which is why this has to walk the
    /// sections rather than read a fixed offset. Anything unexpected falls back to the classic limit:
    /// a reply that is smaller than the client would have accepted costs a retry over TCP, while one
    /// that is larger is simply lost.
    /// </remarks>
    public static int GetMaximumReplySize(ReadOnlySpan<byte> query)
    {
        if (!TryGetQuestionEnd(query, out var offset))
        {
            return ClassicMaximumSize;
        }

        var answers = BinaryPrimitives.ReadUInt16BigEndian(query[6..8]);
        var authorities = BinaryPrimitives.ReadUInt16BigEndian(query[8..10]);
        var additionals = BinaryPrimitives.ReadUInt16BigEndian(query[10..12]);

        for (var i = 0; i < answers + authorities; i++)
        {
            if (!TrySkipRecord(query, ref offset, out _, out _))
            {
                return ClassicMaximumSize;
            }
        }

        for (var i = 0; i < additionals; i++)
        {
            if (!TrySkipRecord(query, ref offset, out var type, out var recordClass))
            {
                return ClassicMaximumSize;
            }

            if (type == OptRecordType)
            {
                return Math.Max((int)recordClass, ClassicMaximumSize);
            }
        }

        return ClassicMaximumSize;
    }

    /// <summary>
    /// Builds the reply that tells a client to ask again over TCP.
    /// </summary>
    /// <param name="query">The query to answer.</param>
    /// <param name="buffer">The buffer to write the reply into.</param>
    /// <param name="length">Receives the length of the reply.</param>
    /// <returns>
    /// <see langword="true"/> if a reply was built; otherwise, <see langword="false"/> and the query
    /// could not be walked.
    /// </returns>
    /// <remarks>
    /// The question is echoed and every other section dropped, which is what the truncated bit means:
    /// not "here is part of the answer" but "the answer did not fit". Windows responds by reopening
    /// the same query over TCP, which this stack carries natively - so an oversized answer costs a
    /// round trip rather than failing.
    /// </remarks>
    public static bool TryBuildTruncatedReply(ReadOnlySpan<byte> query, Span<byte> buffer, out int length)
    {
        length = 0;

        if (!TryGetQuestionEnd(query, out var questionEnd) || buffer.Length < questionEnd)
        {
            return false;
        }

        query[..questionEnd].CopyTo(buffer);

        // QR (a response) and TC (truncated), preserving the query's opcode and recursion-desired
        // bit; RA, because a client that asked for recursion should not be told it was unavailable.
        // Not AA - this is not our answer to give, and claiming authority for it would be a lie a
        // resolver is entitled to cache.
        buffer[2] = (byte)(query[2] | 0x82);
        buffer[3] = (byte)((query[3] & 0x10) | 0x80);

        // Every section but the question, which was copied above.
        buffer[6..12].Clear();

        length = questionEnd;
        return true;
    }

    /// <summary>
    /// Finds where the question section ends.
    /// </summary>
    private static bool TryGetQuestionEnd(ReadOnlySpan<byte> message, out int offset)
    {
        offset = HeaderLength;

        if (message.Length < HeaderLength)
        {
            return false;
        }

        var questions = BinaryPrimitives.ReadUInt16BigEndian(message[4..6]);

        for (var i = 0; i < questions; i++)
        {
            if (!TrySkipName(message, ref offset))
            {
                return false;
            }

            // Type and class.
            offset += 4;
            if (offset > message.Length)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Steps over one resource record, reporting its type and class.
    /// </summary>
    private static bool TrySkipRecord(
        ReadOnlySpan<byte> message,
        ref int offset,
        out ushort type,
        out ushort recordClass)
    {
        type = 0;
        recordClass = 0;

        if (!TrySkipName(message, ref offset) || offset + 10 > message.Length)
        {
            return false;
        }

        type = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset, 2));
        recordClass = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset + 2, 2));
        var dataLength = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset + 8, 2));

        offset += 10 + dataLength;
        return offset <= message.Length;
    }

    /// <summary>
    /// Steps over a domain name.
    /// </summary>
    /// <remarks>
    /// A compression pointer ends the name, so following it is unnecessary here - only the name's
    /// length matters. It is accepted rather than rejected because a pointer in a question is
    /// malformed but not dangerous, and this walk exists to decide a size, not to validate.
    /// </remarks>
    private static bool TrySkipName(ReadOnlySpan<byte> message, ref int offset)
    {
        while (true)
        {
            if (offset >= message.Length)
            {
                return false;
            }

            var label = message[offset];

            if ((label & 0xC0) == 0xC0)
            {
                offset += 2;
                return offset <= message.Length;
            }

            if ((label & 0xC0) != 0)
            {
                // The two reserved label types, which nothing generates.
                return false;
            }

            offset++;

            if (label == 0)
            {
                return true;
            }

            offset += label;
        }
    }
}
