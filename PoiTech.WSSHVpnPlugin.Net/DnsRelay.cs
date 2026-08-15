using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// Carries DNS queries over TCP, so that name resolution survives a tunnel with no UDP.
/// </summary>
/// <remarks>
/// <para>
/// SSH forwards byte streams, so a UDP query has nowhere to go. RFC 7766 makes this tractable: every
/// DNS server that speaks UDP also speaks TCP, with the same message preceded by a two-byte length.
/// So each query becomes a channel, and the reply becomes a datagram again on the way back. The
/// client never learns that anything happened.
/// </para>
/// <para>
/// Not optional. Assigning DNS servers pins the whole machine's name resolution to this tunnel the
/// moment it starts, so without this every name on the system fails to resolve - not just names
/// inside the tunnel.
/// </para>
/// <para>
/// Single-threaded by contract, like everything else the stack owns.
/// </para>
/// </remarks>
internal sealed class DnsRelay
{
    /// <summary>The well-known DNS port.</summary>
    public const ushort Port = 53;

    /// <summary>
    /// How many queries may be in flight at once.
    /// </summary>
    /// <remarks>
    /// A burst of name lookups is a burst of channel opens, each costing a round trip to the SSH
    /// server. Beyond this they are dropped, which a resolver treats as packet loss and retries -
    /// the outcome UDP already has, and better than queueing work that will time out anyway.
    /// </remarks>
    private const int MaximumOutstanding = 16;

    /// <summary>
    /// The largest reply that can be handed back as a single datagram.
    /// </summary>
    /// <remarks>
    /// The tunnel MTU less the IPv4 and UDP headers. Nothing here fragments, so a reply above this
    /// cannot be delivered whatever the client says it would accept.
    /// </remarks>
    private const int MaximumReplySize = 1372;

    /// <summary>How long a query may stay outstanding before it is abandoned.</summary>
    /// <remarks>
    /// Above a resolver's own first-attempt timeout, so a query is normally retried by the client
    /// before this fires. This is the reaper that stops a hung channel leaking, not a retry policy.
    /// </remarks>
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(5);

    private readonly IPacketSink _sink;
    private readonly IStackClock _clock;
    private readonly OpenChannel _open;
    private readonly List<PendingQuery> _queries = new();
    private readonly byte[] _scratch = new byte[1500];

    public DnsRelay(IPacketSink sink, IStackClock clock, OpenChannel open)
    {
        _sink = sink;
        _clock = clock;
        _open = open;
    }

    /// <summary>Begins opening a channel, calling back on the stack's own thread.</summary>
    public delegate void OpenChannel(uint address, ushort port, Action<IByteChannel> onOpened, Action onFailed);

    /// <summary>Gets the number of queries relayed in full.</summary>
    public long Answered { get; private set; }

    /// <summary>Gets the number of replies too large to return as a datagram.</summary>
    public long Truncated { get; private set; }

    /// <summary>Gets the number of queries dropped or abandoned.</summary>
    public long Dropped { get; private set; }

    /// <summary>Gets the number of queries currently in flight.</summary>
    public int Outstanding => _queries.Count;

    /// <summary>
    /// Takes a query addressed to a DNS server.
    /// </summary>
    /// <param name="source">The client's address.</param>
    /// <param name="destination">The DNS server's address.</param>
    /// <param name="datagram">The datagram carrying the query.</param>
    /// <returns><see langword="true"/> if the query was taken.</returns>
    public bool Offer(uint source, uint destination, UdpDatagram datagram)
    {
        var payload = datagram.Payload;

        if (payload.Length < DnsMessage.HeaderLength || _queries.Count >= MaximumOutstanding)
        {
            Dropped++;
            return false;
        }

        var query = new PendingQuery
        {
            ClientAddress = source,
            ClientPort = datagram.SourcePort,
            ServerAddress = destination,
            Message = payload.ToArray(),
            Deadline = _clock.Now + QueryTimeout,
        };

        query.MaximumReply = Math.Min(DnsMessage.GetMaximumReplySize(query.Message), MaximumReplySize);

        // The whole query, framed as RFC 7766 wants it, built once so a partial send can simply
        // resume from an offset.
        query.Request = new byte[sizeof(ushort) + query.Message.Length];
        BinaryPrimitives.WriteUInt16BigEndian(query.Request, (ushort)query.Message.Length);
        query.Message.CopyTo(query.Request, sizeof(ushort));

        _queries.Add(query);

        _open(
            destination,
            Port,
            channel => query.Channel = channel,
            () => query.Failed = true);

        return true;
    }

    /// <summary>
    /// Moves every outstanding query along, and forgets the finished ones.
    /// </summary>
    /// <returns><see langword="true"/> if anything progressed.</returns>
    public bool RunOnce()
    {
        var progressed = false;

        for (var i = _queries.Count - 1; i >= 0; i--)
        {
            var query = _queries[i];
            var finished = Pump(query);

            if (!finished && _clock.Now >= query.Deadline)
            {
                Dropped++;
                finished = true;
            }

            if (!finished)
            {
                continue;
            }

            query.Channel?.Dispose();
            _queries.RemoveAt(i);
            progressed = true;
        }

        return progressed;
    }

    /// <summary>
    /// Moves one query along.
    /// </summary>
    /// <returns><see langword="true"/> if it is finished, one way or the other.</returns>
    private bool Pump(PendingQuery query)
    {
        if (query.Failed)
        {
            // No channel, so nothing to say to the client. A resolver reads silence as loss and asks
            // again, which is the same thing that happens when a UDP query is dropped.
            Dropped++;
            return true;
        }

        // A reply that was built but could not be delivered because the platform's queue was full.
        if (query.ReplyLength > 0)
        {
            return SendReply(query);
        }

        var channel = query.Channel;
        if (channel is null)
        {
            return false;
        }

        while (query.Sent < query.Request!.Length)
        {
            var result = channel.TrySend(
                query.Request,
                query.Sent,
                query.Request.Length - query.Sent,
                out var written);

            query.Sent += written;

            if (result == ByteChannelSendResult.Closed)
            {
                Dropped++;
                return true;
            }

            if (result == ByteChannelSendResult.Full || written == 0)
            {
                break;
            }
        }

        if (query.Sent < query.Request.Length)
        {
            return false;
        }

        while (channel.TryRead(out var data))
        {
            Append(query, data);

            if (channel.Advance(data.Count))
            {
                channel.FlushWindowCredit();
            }

            if (TryBuildReply(query))
            {
                return SendReply(query);
            }

            if (query.Failed)
            {
                Dropped++;
                return true;
            }
        }

        if (channel.IsPeerEof || !channel.IsOpen)
        {
            // The server hung up mid-reply. Nothing partial is worth returning: a DNS message is
            // only meaningful whole.
            Dropped++;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Copies what the channel gave us into the reply buffer, discarding any excess.
    /// </summary>
    /// <remarks>
    /// Excess can only appear once the reply is already known to be too large to return, and in that
    /// case the rest of it is never read - so dropping it here costs nothing and keeps the buffer a
    /// fixed size.
    /// </remarks>
    private static void Append(PendingQuery query, ArraySegment<byte> data)
    {
        var space = query.Reply.Length - query.Received;
        var take = Math.Min(space, data.Count);

        if (take > 0)
        {
            data.AsSpan()[..take].CopyTo(query.Reply.AsSpan(query.Received));
        }

        query.Received += data.Count;
    }

    /// <summary>
    /// Decides whether the reply is complete, and prepares it for delivery.
    /// </summary>
    /// <returns><see langword="true"/> if there is now a reply to send.</returns>
    private bool TryBuildReply(PendingQuery query)
    {
        if (query.Received < sizeof(ushort))
        {
            return false;
        }

        var declared = BinaryPrimitives.ReadUInt16BigEndian(query.Reply);

        if (declared > query.MaximumReply)
        {
            // Too large for one datagram. Say so properly rather than dropping it: a truncated reply
            // makes the client ask again over TCP, which this stack carries natively.
            Truncated++;

            if (!DnsMessage.TryBuildTruncatedReply(query.Message, query.Reply, out var length))
            {
                query.Failed = true;
                return false;
            }

            query.ReplyOffset = 0;
            query.ReplyLength = length;
            return true;
        }

        if (query.Received < sizeof(ushort) + declared)
        {
            return false;
        }

        Answered++;
        query.ReplyOffset = sizeof(ushort);
        query.ReplyLength = declared;
        return true;
    }

    /// <summary>
    /// Hands a finished reply back as a datagram from the server the client asked.
    /// </summary>
    /// <returns>
    /// <see langword="true"/> if the query is finished with - either delivered, or given up on.
    /// </returns>
    private bool SendReply(PendingQuery query)
    {
        if (!_sink.CanAccept)
        {
            // Retried next pass. The reply is already built and the deadline still applies, so this
            // cannot spin forever.
            return false;
        }

        const int UdpOffset = Ipv4Packet.MinimumHeaderLength;
        var payload = query.Reply.AsSpan(query.ReplyOffset, query.ReplyLength);

        payload.CopyTo(_scratch.AsSpan(UdpOffset + UdpDatagram.HeaderLength));

        var udpLength = UdpDatagram.Write(
            _scratch.AsSpan(UdpOffset),
            query.ServerAddress,
            query.ClientAddress,
            Port,
            query.ClientPort,
            payload.Length);

        var total = Ipv4Packet.Write(
            _scratch,
            IpProtocol.Udp,
            query.ServerAddress,
            query.ClientAddress,
            udpLength);

        _ = _sink.TryWrite(_scratch.AsSpan(0, total));
        return true;
    }

    /// <summary>
    /// One query, from the datagram that started it to the datagram that answers it.
    /// </summary>
    private sealed class PendingQuery
    {
        /// <summary>The reply buffer, sized for the largest reply that could be delivered.</summary>
        public byte[] Reply { get; } = new byte[sizeof(ushort) + MaximumReplySize];

        public uint ClientAddress { get; init; }

        public ushort ClientPort { get; init; }

        public uint ServerAddress { get; init; }

        /// <summary>The query as the client sent it, kept for building a truncated reply.</summary>
        public byte[] Message { get; init; } = Array.Empty<byte>();

        /// <summary>The query with its length prefix, as it goes onto the channel.</summary>
        public byte[]? Request { get; set; }

        public TimeSpan Deadline { get; init; }

        public int MaximumReply { get; set; }

        public IByteChannel? Channel { get; set; }

        public bool Failed { get; set; }

        public int Sent { get; set; }

        public int Received { get; set; }

        public int ReplyOffset { get; set; }

        public int ReplyLength { get; set; }
    }
}
