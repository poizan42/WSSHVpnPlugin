using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// One DNS server's channel, and the queries pipelined onto it.
/// </summary>
/// <remarks>
/// <para>
/// The framing is the delicate part. RFC 7766 puts a two-byte length before every message and allows
/// replies to come back in any order, so this has to consume <em>exactly</em> that many bytes for
/// each one: stop short or overrun by one and every later reply on the channel is garbage, because
/// the next length is read from the middle of a message. That is why an oversize reply is still
/// consumed in full rather than abandoned - the bytes have to leave the stream even when the answer
/// cannot be used.
/// </para>
/// <para>
/// Identifiers are ours, not the client's. Two clients can pick the same one, and out-of-order
/// replies mean the only way back to the right query is the identifier, so each query gets one from
/// here and the client's is restored on the way out.
/// </para>
/// </remarks>
internal sealed class ServerLink
{
    /// <summary>How many queries may be waiting for an answer on one channel.</summary>
    /// <remarks>
    /// A bound on memory and on what a single unresponsive server can hold, not on concurrency:
    /// pipelined queries cost a dictionary entry each rather than a channel each.
    /// </remarks>
    public const int MaximumOutstanding = 64;

    /// <summary>How long a query may stay outstanding before it is abandoned.</summary>
    public static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(5);

    private readonly Dictionary<ushort, PendingQuery> _queries = new();
    private readonly List<ushort> _expired = new();
    private readonly Queue<byte[]> _outgoing = new();

    // Reassembly state. The prefix is accumulated separately because it can be split across reads
    // just as easily as the body can.
    private readonly byte[] _prefix = new byte[sizeof(ushort)];
    private readonly byte[] _body = new byte[1372];
    private int _prefixFilled;
    private int _bodyRemaining;
    private int _bodyFilled;
    private bool _bodyOversize;
    private bool _reading;

    private int _sendOffset;
    private ushort _nextId;
    private TimeSpan _lastBusy;

    public ServerLink(uint serverAddress)
    {
        ServerAddress = serverAddress;
        ReplyBuffer = new byte[1372];
    }

    /// <summary>Gets the DNS server this channel talks to.</summary>
    public uint ServerAddress { get; }

    /// <summary>Gets or sets the channel, once it is open.</summary>
    public IByteChannel? Channel { get; set; }

    /// <summary>Gets or sets a value indicating whether an open is in flight.</summary>
    public bool Opening { get; set; }

    /// <summary>Gets or sets a value indicating whether the last open failed.</summary>
    public bool Failed { get; set; }

    /// <summary>Gets a value indicating whether this link has been given up on.</summary>
    public bool Abandoned { get; private set; }

    /// <summary>Gets the buffer a finished reply is built in.</summary>
    public byte[] ReplyBuffer { get; }

    /// <summary>Gets the length of the reply waiting to be delivered.</summary>
    public int ReplyLength { get; private set; }

    /// <summary>Gets the address the waiting reply goes to.</summary>
    public uint ReplyClientAddress { get; private set; }

    /// <summary>Gets the port the waiting reply goes to.</summary>
    public ushort ReplyClientPort { get; private set; }

    /// <summary>Gets a value indicating whether a reply is built and waiting for room downstream.</summary>
    public bool HasReplyPending => ReplyLength > 0;

    /// <summary>Gets a value indicating whether anything is still queued to send.</summary>
    public bool HasQueuedRequests => _outgoing.Count > 0;

    /// <summary>Gets how many queries are still waiting for an answer.</summary>
    public int LiveCount
    {
        get
        {
            var live = 0;

            foreach (var query in _queries.Values)
            {
                if (!query.Expired)
                {
                    live++;
                }
            }

            return live;
        }
    }

    /// <summary>
    /// Takes a query, if there is room for it.
    /// </summary>
    /// <returns><see langword="true"/> if it was accepted.</returns>
    public bool TryAccept(
        uint clientAddress,
        ushort clientPort,
        ReadOnlySpan<byte> message,
        TimeSpan now,
        out PendingQuery query)
    {
        query = null!;

        if (LiveCount >= MaximumOutstanding)
        {
            return false;
        }

        var id = NextIdentifier();

        query = new PendingQuery
        {
            ClientAddress = clientAddress,
            ClientPort = clientPort,
            ClientId = BinaryPrimitives.ReadUInt16BigEndian(message),
            Message = message.ToArray(),
            Deadline = now + QueryTimeout,
        };

        _queries[id] = query;

        // Framed once, with our identifier in place of the client's, so a partial send resumes from
        // an offset rather than rebuilding anything.
        var framed = new byte[sizeof(ushort) + message.Length];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)message.Length);
        message.CopyTo(framed.AsSpan(sizeof(ushort)));
        BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(sizeof(ushort)), id);

        _outgoing.Enqueue(framed);
        return true;
    }

    /// <summary>
    /// Writes what the channel's window allows, in order.
    /// </summary>
    /// <param name="sent">Set if any bytes went.</param>
    /// <returns><see langword="true"/> if the channel is still usable.</returns>
    public bool SendQueued(out bool sent)
    {
        sent = false;

        var channel = Channel;
        if (channel is null)
        {
            return false;
        }

        while (_outgoing.Count > 0)
        {
            var head = _outgoing.Peek();
            var result = channel.TrySend(head, _sendOffset, head.Length - _sendOffset, out var written);

            if (written > 0)
            {
                _sendOffset += written;
                sent = true;
            }

            if (_sendOffset >= head.Length)
            {
                _ = _outgoing.Dequeue();
                _sendOffset = 0;
                continue;
            }

            // Anything left of this message must go before the next one starts, or two
            // length-framed messages interleave and the server sees neither.
            if (result == ByteChannelSendResult.Closed)
            {
                return false;
            }

            break;
        }

        return true;
    }

    /// <summary>
    /// Feeds received bytes through the reassembler, completing whole messages as they appear.
    /// </summary>
    /// <returns>How many bytes were consumed.</returns>
    public int Consume(ReadOnlySpan<byte> data, DnsRelay relay)
    {
        var consumed = 0;

        while (!data.IsEmpty)
        {
            if (HasReplyPending)
            {
                // No room to put another answer yet; stop rather than consume what we cannot use.
                break;
            }

            if (!_reading)
            {
                var take = Math.Min(_prefix.Length - _prefixFilled, data.Length);
                data[..take].CopyTo(_prefix.AsSpan(_prefixFilled));
                _prefixFilled += take;
                data = data[take..];
                consumed += take;

                if (_prefixFilled < _prefix.Length)
                {
                    break;
                }

                _bodyRemaining = BinaryPrimitives.ReadUInt16BigEndian(_prefix);
                _bodyFilled = 0;
                _bodyOversize = _bodyRemaining > _body.Length;
                _prefixFilled = 0;
                _reading = true;

                if (_bodyRemaining == 0)
                {
                    // A length of zero is meaningless, but it must not spin.
                    _reading = false;
                    continue;
                }
            }

            var chunk = Math.Min(_bodyRemaining, data.Length);
            var store = Math.Min(chunk, _body.Length - _bodyFilled);

            if (store > 0)
            {
                data[..store].CopyTo(_body.AsSpan(_bodyFilled));
                _bodyFilled += store;
            }

            _bodyRemaining -= chunk;
            data = data[chunk..];
            consumed += chunk;

            if (_bodyRemaining == 0)
            {
                _reading = false;
                relay.OnMessage(this, _body.AsSpan(0, _bodyFilled), _bodyOversize);
            }
        }

        return consumed;
    }

    /// <summary>Claims the query an identifier belongs to, if it is still live.</summary>
    public bool TryTake(ushort id, TimeSpan now, TimeSpan quarantine, out PendingQuery query)
    {
        if (!_queries.TryGetValue(id, out query!) || query.Expired)
        {
            query = null!;
            return false;
        }

        // Kept, not removed: the identifier stays reserved for a while so a duplicate arriving
        // afterwards cannot be delivered as somebody else's answer.
        query.Expired = true;
        query.Deadline = now + quarantine;
        return true;
    }

    /// <summary>Records a reply built and waiting for room downstream.</summary>
    public void SetReplyPending(PendingQuery query, int length)
    {
        ReplyClientAddress = query.ClientAddress;
        ReplyClientPort = query.ClientPort;
        ReplyLength = length;
    }

    /// <summary>Clears the waiting reply once it has been delivered.</summary>
    public void ClearReplyPending()
    {
        ReplyLength = 0;
    }

    /// <summary>
    /// Abandons queries past their deadline, and forgets identifiers past their quarantine.
    /// </summary>
    /// <returns>How many queries were abandoned.</returns>
    public int Expire(TimeSpan now, TimeSpan quarantine)
    {
        var abandoned = 0;

        foreach (var pair in _queries)
        {
            if (!pair.Value.Expired)
            {
                if (now >= pair.Value.Deadline)
                {
                    pair.Value.Expired = true;
                    pair.Value.Deadline = now + quarantine;
                    abandoned++;
                }

                continue;
            }

            if (now >= pair.Value.Deadline)
            {
                _expired.Add(pair.Key);
            }
        }

        foreach (var id in _expired)
        {
            _ = _queries.Remove(id);
        }

        _expired.Clear();
        return abandoned;
    }

    /// <summary>Gives up on everything in flight, and reports how many were lost.</summary>
    public int AbandonAll()
    {
        var lost = LiveCount;

        _queries.Clear();
        _outgoing.Clear();
        _sendOffset = 0;
        _prefixFilled = 0;
        _bodyRemaining = 0;
        _bodyFilled = 0;
        _reading = false;
        ReplyLength = 0;

        return lost;
    }

    /// <summary>
    /// Gets a value indicating whether this link has nothing left to do and has been idle long
    /// enough to close.
    /// </summary>
    public bool IsDone(TimeSpan now, TimeSpan idleTimeout)
    {
        if (_queries.Count > 0 || _outgoing.Count > 0 || HasReplyPending || Opening)
        {
            _lastBusy = now;
            return false;
        }

        return now - _lastBusy >= idleTimeout;
    }

    /// <summary>Releases the channel.</summary>
    public void Dispose()
    {
        Abandoned = true;
        Channel?.Dispose();
        Channel = null;
    }

    /// <summary>
    /// Picks an identifier nothing outstanding or quarantined is using.
    /// </summary>
    private ushort NextIdentifier()
    {
        for (var attempt = 0; attempt <= ushort.MaxValue; attempt++)
        {
            var candidate = _nextId++;

            if (!_queries.ContainsKey(candidate))
            {
                return candidate;
            }
        }

        // Unreachable while the outstanding cap is far below 65536, but a wrong answer here would be
        // a reply delivered to the wrong client, so it fails instead.
        throw new InvalidOperationException("No DNS message identifier is free.");
    }
}

/// <summary>
/// One query, from the datagram that started it to the datagram that answers it.
/// </summary>
internal sealed class PendingQuery
{
    /// <summary>Gets the client's address.</summary>
    public uint ClientAddress { get; init; }

    /// <summary>Gets the client's port.</summary>
    public ushort ClientPort { get; init; }

    /// <summary>Gets the identifier the client used, which its reply must carry.</summary>
    public ushort ClientId { get; init; }

    /// <summary>Gets the query as the client sent it, kept for building a truncated reply.</summary>
    public byte[] Message { get; init; } = Array.Empty<byte>();

    /// <summary>Gets or sets when this query is abandoned, then when its identifier is released.</summary>
    public TimeSpan Deadline { get; set; }

    /// <summary>Gets or sets the largest reply the client will accept.</summary>
    public int MaximumReply { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this query is finished with - answered, or given up
    /// on - and is only holding its identifier.
    /// </summary>
    public bool Expired { get; set; }
}
