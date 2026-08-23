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
/// </para>
/// <para>
/// One channel per <em>server</em>, not per query, with queries pipelined onto it. The first version
/// opened a channel per query, and measured against a real tunnel that was the dominant cost: 60 of
/// 77 refused channel opens in one run were DNS, all of them inside the first minute, because a
/// browser resolving a page's worth of names outruns any sane limit on concurrent opens. Pipelining
/// turns a burst of opens into a burst of writes, and removes the open's round trip from every
/// lookup's latency.
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
    /// How long an abandoned query's identifier stays reserved.
    /// </summary>
    /// <remarks>
    /// A late reply must not be delivered as the answer to whichever query inherited its identifier.
    /// Holding the identifier past the deadline makes that impossible rather than unlikely.
    /// </remarks>
    private static readonly TimeSpan Quarantine = TimeSpan.FromSeconds(10);

    /// <summary>How long a channel with nothing to do is kept before it is closed.</summary>
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(60);

    private readonly IPacketSink _sink;
    private readonly IStackClock _clock;
    private readonly OpenChannel _open;
    private readonly Dictionary<IpAddr, ServerLink> _links = new();
    private readonly List<IpAddr> _finished = new();
    private readonly byte[] _scratch;

    /// <summary>The tunnel MTU, from which each link derives its reply cap.</summary>
    private readonly int _mtu;

    public DnsRelay(IPacketSink sink, IStackClock clock, OpenChannel open, int mtu)
    {
        _sink = sink;
        _clock = clock;
        _open = open;
        _mtu = mtu;
        _scratch = new byte[mtu];
    }

    /// <summary>Begins opening a channel, calling back on the stack's own thread.</summary>
    public delegate void OpenChannel(IpAddr address, ushort port, Action<IByteChannel> onOpened, Action onFailed);

    /// <summary>Gets the number of queries relayed in full.</summary>
    public long Answered { get; private set; }

    /// <summary>Gets the number of replies too large to return as a datagram.</summary>
    public long Truncated { get; private set; }

    /// <summary>Gets the number of queries dropped or abandoned.</summary>
    public long Dropped { get; private set; }

    /// <summary>Gets the number of queries currently awaiting an answer.</summary>
    public int Outstanding
    {
        get
        {
            var total = 0;

            foreach (var link in _links.Values)
            {
                total += link.LiveCount;
            }

            return total;
        }
    }

    /// <summary>Gets the number of server channels currently held.</summary>
    public int Channels => _links.Count;

    /// <summary>
    /// Takes a query addressed to a DNS server.
    /// </summary>
    /// <param name="source">The client's address.</param>
    /// <param name="destination">The DNS server's address.</param>
    /// <param name="datagram">The datagram carrying the query.</param>
    /// <returns><see langword="true"/> if the query was taken.</returns>
    public bool Offer(IpAddr source, IpAddr destination, UdpDatagram datagram)
    {
        var payload = datagram.Payload;

        if (payload.Length < DnsMessage.HeaderLength)
        {
            Dropped++;
            return false;
        }

        if (!_links.TryGetValue(destination, out var link))
        {
            // The largest reply that can go back as one datagram: the MTU less this family's IP
            // header and the UDP header. Nothing here fragments, so a reply above this cannot be
            // delivered whatever the client says it would accept.
            var replyCapacity = _mtu - destination.HeaderLength - UdpDatagram.HeaderLength;

            link = new ServerLink(destination, replyCapacity);
            _links[destination] = link;
            BeginOpen(link);
        }

        if (!link.TryAccept(source, datagram.SourcePort, payload, _clock.Now, out var query))
        {
            Dropped++;
            return false;
        }

        query.MaximumReply = Math.Min(DnsMessage.GetMaximumReplySize(query.Message), link.ReplyCapacity);
        return true;
    }

    /// <summary>
    /// Moves every server channel along, and forgets the ones with nothing left to do.
    /// </summary>
    /// <returns><see langword="true"/> if anything progressed.</returns>
    public bool RunOnce()
    {
        var progressed = false;
        var now = _clock.Now;

        foreach (var pair in _links)
        {
            if (Pump(pair.Value, now))
            {
                progressed = true;
            }

            if (pair.Value.IsDone(now, IdleTimeout))
            {
                _finished.Add(pair.Key);
            }
        }

        foreach (var address in _finished)
        {
            _links[address].Dispose();
            _ = _links.Remove(address);
            progressed = true;
        }

        _finished.Clear();
        return progressed;
    }

    /// <summary>Releases every channel, for teardown.</summary>
    public void Dispose()
    {
        foreach (var link in _links.Values)
        {
            link.Dispose();
        }

        _links.Clear();
    }

    private void BeginOpen(ServerLink link)
    {
        link.Opening = true;

        _open(
            link.ServerAddress,
            Port,
            channel =>
            {
                // The link may have been given up on while the open was in flight; a channel handed
                // to a forgotten link is one nothing will ever close.
                if (link.Abandoned)
                {
                    channel.Dispose();
                    return;
                }

                link.Opening = false;
                link.Channel = channel;
            },
            () =>
            {
                link.Opening = false;
                link.Failed = true;
            });
    }

    /// <summary>
    /// Moves one server's channel along: send what is queued, read what has arrived, reap what has
    /// timed out.
    /// </summary>
    private bool Pump(ServerLink link, TimeSpan now)
    {
        var expired = link.Expire(now, Quarantine);
        Dropped += expired;
        var progressed = expired > 0;

        if (link.Failed)
        {
            // No channel and no prospect of one. Everything waiting on it is loss as far as the
            // client is concerned, which is what it would have seen from a dropped datagram.
            Dropped += link.AbandonAll();
            link.Failed = false;
            link.Channel = null;

            if (link.LiveCount > 0 || link.HasQueuedRequests)
            {
                BeginOpen(link);
            }

            return true;
        }

        var channel = link.Channel;
        if (channel is null)
        {
            if (!link.Opening && (link.LiveCount > 0 || link.HasQueuedRequests))
            {
                BeginOpen(link);
                progressed = true;
            }

            return progressed;
        }

        if (link.SendQueued(out var sent) && sent)
        {
            progressed = true;
        }

        if (ReceiveInto(link, channel))
        {
            progressed = true;
        }

        if (!channel.IsOpen || channel.IsPeerEof)
        {
            // The server hung up. Whatever was in flight is gone; a fresh channel opens on the next
            // query rather than now, so a server that closes on every request cannot spin.
            Dropped += link.AbandonAll();
            channel.Dispose();
            link.Channel = null;
            progressed = true;
        }

        return progressed;
    }

    /// <summary>
    /// Reads whatever the channel has, completing every whole message in it.
    /// </summary>
    private bool ReceiveInto(ServerLink link, IByteChannel channel)
    {
        var progressed = false;

        while (true)
        {
            // A reply that could not be handed to the platform blocks the stream deliberately:
            // reading on would consume the bytes behind it with nowhere to put the result.
            if (link.HasReplyPending && !DeliverPending(link))
            {
                return progressed;
            }

            if (!channel.TryRead(out var data) || data.Count == 0)
            {
                return progressed;
            }

            var consumed = link.Consume(data.AsSpan(), this);
            progressed = true;

            if (channel.Advance(consumed))
            {
                channel.FlushWindowCredit();
            }

            if (consumed < data.Count)
            {
                // Stopped early, which only happens when a reply is waiting on the sink.
                return progressed;
            }
        }
    }

    /// <summary>
    /// Completes one reassembled message: matches it to its query and answers the client.
    /// </summary>
    /// <remarks>
    /// Called by <see cref="ServerLink"/> as it reassembles, because only the relay owns the sink and
    /// the counters.
    /// </remarks>
    internal void OnMessage(ServerLink link, ReadOnlySpan<byte> message, bool oversize)
    {
        if (message.Length < DnsMessage.HeaderLength)
        {
            Dropped++;
            return;
        }

        var id = BinaryPrimitives.ReadUInt16BigEndian(message);

        if (!link.TryTake(id, _clock.Now, Quarantine, out var query))
        {
            // A reply to a query that timed out, or one nobody asked for. Its bytes are consumed
            // either way - the stream has to stay in step.
            Dropped++;
            return;
        }

        if (oversize || message.Length > query.MaximumReply)
        {
            Truncated++;

            if (!DnsMessage.TryBuildTruncatedReply(query.Message, link.ReplyBuffer, out var length))
            {
                Dropped++;
                return;
            }

            link.SetReplyPending(query, length);
        }
        else
        {
            Answered++;
            message.CopyTo(link.ReplyBuffer);

            // The client's own identifier goes back, not ours.
            BinaryPrimitives.WriteUInt16BigEndian(link.ReplyBuffer, query.ClientId);
            link.SetReplyPending(query, message.Length);
        }

        _ = DeliverPending(link);
    }

    /// <summary>
    /// Hands a finished reply back as a datagram from the server the client asked.
    /// </summary>
    /// <returns><see langword="true"/> if it went; otherwise the sink was full and it still waits.</returns>
    private bool DeliverPending(ServerLink link)
    {
        if (!link.HasReplyPending)
        {
            return true;
        }

        if (!_sink.CanAccept)
        {
            return false;
        }

        var udpOffset = link.ServerAddress.HeaderLength;
        var payload = link.ReplyBuffer.AsSpan(0, link.ReplyLength);

        payload.CopyTo(_scratch.AsSpan(udpOffset + UdpDatagram.HeaderLength));

        var udpLength = UdpDatagram.Write(
            _scratch.AsSpan(udpOffset),
            link.ServerAddress,
            link.ReplyClientAddress,
            Port,
            link.ReplyClientPort,
            payload.Length);

        var total = IpHeader.Write(
            _scratch,
            IpProtocol.Udp,
            link.ServerAddress,
            link.ReplyClientAddress,
            udpLength);

        _ = _sink.TryWrite(_scratch.AsSpan(0, total));
        link.ClearReplyPending();
        return true;
    }
}
