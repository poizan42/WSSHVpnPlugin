using System;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// One TCP connection, terminated locally and carried onward as a byte stream.
/// </summary>
/// <remarks>
/// <para>
/// We are the server side of every connection: the operating system inside the tunnel connects to
/// somewhere, and this answers on that somewhere's behalf while an <see cref="IByteChannel"/> carries
/// the bytes. That makes the state machine a good deal smaller than a general one - there is no
/// active open, and no simultaneous open to worry about.
/// </para>
/// <para>
/// Single-threaded by contract. Everything here runs on the stack's own thread, so nothing locks,
/// and nothing here may block: the send path reports what it could not take rather than waiting.
/// </para>
/// </remarks>
internal sealed class TcpFlow
{
    /// <summary>What we advertise, and the most we will buffer from the peer.</summary>
    private const ushort ReceiveWindow = 32768;

    /// <summary>Our MTU less the IPv4 and TCP headers.</summary>
    private const ushort OurMaximumSegmentSize = 1360;

    /// <summary>
    /// How many segments one flow may send in a single visit before yielding.
    /// </summary>
    /// <remarks>
    /// Without this a flow drains its channel until the sink refuses, so the sink's capacity becomes
    /// the fairness quantum between inbound and outbound - and whatever thread drives the loop stops
    /// draining what the operating system is sending while it does. Raising the inbound queue from 48
    /// to 512 demonstrated the cost: the outbound queue overflowed and dropped 4566 packets in two
    /// minutes, losing acknowledgements and killing the connections it was meant to speed up. A
    /// bound here keeps the two directions independent, so either queue can be sized on its own
    /// merits.
    /// </remarks>
    private const int InboundQuantum = 8;

    /// <summary>
    /// How long an acknowledgement may wait for something to travel with.
    /// </summary>
    /// <remarks>
    /// The usual value. Both ends are on this machine, so the round trip is negligible and the delay
    /// is pure latency - but a bare acknowledgement per segment is a packet the platform has to carry
    /// for nothing, and waiting lets it ride along with the response the peer is usually about to
    /// get anyway.
    /// </remarks>
    private static readonly TimeSpan AckDelay = TimeSpan.FromMilliseconds(40);

    private readonly TcpFlowKey _key;
    private readonly IPacketSink _sink;
    private readonly IStackClock _clock;
    private readonly byte[] _scratch = new byte[1500];

    /// <summary>How long to wait for an acknowledgement before resending, initially.</summary>
    /// <remarks>Doubled on each expiry, so a dead peer costs retries, not a flood.</remarks>
    private static readonly TimeSpan InitialRetransmitTimeout = TimeSpan.FromMilliseconds(200);

    private static readonly TimeSpan MaximumRetransmitTimeout = TimeSpan.FromSeconds(2);

    private IByteChannel? _channel;
    private TcpState _state;
    private uint _sendNext;
    private uint _sendUnacknowledged;
    private uint _peerWindow;
    private uint _receiveNext;
    private bool _finSent;
    private TimeSpan _retransmitAt;
    private TimeSpan _retransmitInterval = InitialRetransmitTimeout;
    private ushort _peerMaximumSegmentSize = 536;
    private bool _channelEofSent;
    private bool _ackDue;
    private TimeSpan _ackDueAt;

    public TcpFlow(TcpFlowKey key, IPacketSink sink, IStackClock clock)
    {
        _key = key;
        _sink = sink;
        _clock = clock;
        _state = TcpState.Listen;
    }

    /// <summary>Gets the flow's current state.</summary>
    public TcpState State => _state;

    /// <summary>Gets a value indicating whether the flow is finished and may be forgotten.</summary>
    public bool IsFinished => _state == TcpState.Closed;

    /// <summary>Gets the maximum segment size the peer advertised.</summary>
    public ushort PeerMaximumSegmentSize => _peerMaximumSegmentSize;

    /// <summary>
    /// Takes a segment addressed to this flow.
    /// </summary>
    /// <param name="tcp">The segment.</param>
    /// <returns>
    /// <see langword="true"/> if a channel should now be opened for this flow; otherwise,
    /// <see langword="false"/>.
    /// </returns>
    public bool Accept(in TcpSegment tcp)
    {
        var flags = tcp.Flags;

        if ((flags & TcpFlags.Rst) != 0)
        {
            // The peer has given up. Nothing to answer, and nothing to half-close.
            Abort();
            return false;
        }

        if (_state == TcpState.Listen)
        {
            if ((flags & TcpFlags.Syn) == 0)
            {
                // Anything but a SYN on an unknown flow gets a reset, which is what tells the peer
                // to stop retrying rather than waiting out its own timeout.
                SendReset(tcp);
                return false;
            }

            _receiveNext = tcp.SequenceNumber + 1;   // the SYN occupies a sequence number
            _sendNext = InitialSendSequence(_key);
            _sendUnacknowledged = _sendNext;
            _peerWindow = tcp.WindowSize;

            if (tcp.TryGetMaximumSegmentSize(out var mss) && mss > 0)
            {
                _peerMaximumSegmentSize = mss;
            }

            _state = TcpState.SynReceived;

            // No SYN-ACK yet: the channel has to be open first, or we would be accepting a
            // connection we cannot serve.
            return true;
        }

        if ((flags & TcpFlags.Syn) != 0 && _state == TcpState.SynReceived)
        {
            // A retransmitted SYN while the channel is still opening. Nothing to do; answering
            // early is exactly what we are avoiding.
            return false;
        }

        if ((flags & TcpFlags.Ack) != 0)
        {
            // The peer's view of what it has received and what more it can take. Both matter to
            // the send side: ignoring the advertised window worked at low rates and then cost a
            // whole download at higher ones - a burst past what the peer would buffer was dropped,
            // and with no retransmission on this path a dropped segment wedges the flow for good.
            // Not sending it in the first place is the fix that does not need a retransmit timer.
            var acknowledged = tcp.AcknowledgementNumber;

            if ((int)(acknowledged - _sendUnacknowledged) > 0 && (int)(acknowledged - _sendNext) <= 0)
            {
                var delta = acknowledged - _sendUnacknowledged;
                _sendUnacknowledged = acknowledged;

                // Only now are the channel's bytes released: the buffer between the last
                // acknowledgement and _sendNext is the retransmit buffer, and releasing it on send
                // is how a lost segment became a permanently wedged flow. A FIN occupies a sequence
                // number but no buffer, so its acknowledgement releases nothing.
                var dataDelta = delta;
                if (_finSent && acknowledged == _sendNext)
                {
                    dataDelta--;
                }

                if (dataDelta > 0 && _channel is { } channel)
                {
                    if (channel.Advance((int)dataDelta))
                    {
                        channel.FlushWindowCredit();
                    }
                }

                // Progress resets the clock and the backoff.
                _retransmitInterval = InitialRetransmitTimeout;
                _retransmitAt = _clock.Now + _retransmitInterval;
            }

            _peerWindow = tcp.WindowSize;
        }

        if (tcp.SequenceNumber != _receiveNext && tcp.Payload.Length > 0)
        {
            // Out of order. Re-acknowledge what we do have and let the peer retransmit; holding a
            // reassembly queue is not worth it when the peer is on the same machine.
            SendAck();
            return false;
        }

        var accepted = 0;

        if (tcp.Payload.Length > 0)
        {
            accepted = DeliverToChannel(tcp.Payload);

            if (accepted < tcp.Payload.Length)
            {
                // The channel is full. Acknowledge only what went, immediately rather than after a
                // delay, so the peer learns the window has closed without waiting.
                SendAck();
                return false;
            }
        }

        if ((flags & TcpFlags.Fin) != 0)
        {
            _receiveNext++;

            if (_state == TcpState.FinWait)
            {
                // We closed first and the peer has now followed. Both directions are done, so the
                // flow is finished rather than half-closed - it just has to acknowledge this last
                // FIN before it goes. There is no TIME-WAIT: see the note on TcpState.
                SendAck();

                // Still worth saying explicitly, even though the channel is about to be disposed:
                // this is the client reporting it will send no more, and it is the last chance to
                // pass that on as itself rather than as a close.
                SendChannelEof();
                Finish();
                return false;
            }

            if (_state == TcpState.Established)
            {
                _state = TcpState.CloseWait;
            }

            // A FIN is acknowledged at once: nothing more is coming to piggyback on.
            SendAck();
            SendChannelEof();
            return false;
        }

        if (_state == TcpState.LastAck && tcp.AcknowledgementNumber == _sendNext)
        {
            // Our FIN is acknowledged and the peer's arrived long ago. Nothing is left to carry.
            Finish();
            return false;
        }

        if (accepted > 0)
        {
            ScheduleAck();
        }

        return false;
    }

    /// <summary>
    /// Attaches the channel once it has opened, and completes the handshake.
    /// </summary>
    /// <param name="channel">The channel.</param>
    public void OnChannelOpened(IByteChannel channel)
    {
        if (_state != TcpState.SynReceived)
        {
            // The flow was reset or closed while the channel was opening.
            channel.Dispose();
            return;
        }

        _channel = channel;
        _state = TcpState.Established;

        // The SYN-ACK carries our MSS. Omitting it leaves the peer assuming 536, which halves
        // throughput while appearing to work perfectly.
        SendSegment(TcpFlags.Syn | TcpFlags.Ack, ReadOnlySpan<byte>.Empty, OurMaximumSegmentSize);
        _sendNext++;

        // Counted as acknowledged at once: a SYN occupies a sequence number but no channel bytes,
        // so the acknowledgement-driven release must never see it, and a lost SYN-ACK is recovered
        // by the peer retransmitting its SYN rather than by us.
        _sendUnacknowledged = _sendNext;
    }

    /// <summary>
    /// Reports that the channel could not be opened.
    /// </summary>
    public void OnChannelFailed()
    {
        // A refusal has to look like a refusal: without this the peer retries its SYN until its own
        // connect timeout, which is many seconds of apparently nothing happening.
        SendSegment(TcpFlags.Rst | TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
        _state = TcpState.Closed;
    }

    /// <summary>
    /// Moves whatever the channel has received back to the operating system.
    /// </summary>
    /// <returns><see langword="true"/> if any progress was made.</returns>
    public bool PumpInbound()
    {
        var channel = _channel;
        if (channel is null || _state is not (TcpState.Established or TcpState.CloseWait))
        {
            return false;
        }

        var progressed = false;

        // An acknowledgement that has waited long enough goes now. Sending data below carries the
        // current acknowledgement number with it anyway, so this only fires when there is nothing
        // to piggyback on.
        if (_ackDue && _clock.Now >= _ackDueAt)
        {
            SendAck();
            progressed = true;
        }

        // A retransmission timeout rewinds the send pointer to the last acknowledged byte, and the
        // loop below resends from there - the channel's buffer still holds everything unreleased,
        // which is the whole reason releasing waits for the acknowledgement. Loss is real on this
        // path: at 30 Mbit/s a download died mid-transfer with every queue healthy, because one
        // dropped segment was never sent again.
        if (_sendNext != _sendUnacknowledged && _clock.Now >= _retransmitAt)
        {
            _sendNext = _sendUnacknowledged;
            _retransmitInterval = _retransmitInterval >= MaximumRetransmitTimeout
                ? MaximumRetransmitTimeout
                : _retransmitInterval + _retransmitInterval;
            _retransmitAt = _clock.Now + _retransmitInterval;

            if (_finSent)
            {
                // The FIN was in flight too. It carries no buffer bytes, so it is simply sent
                // again once the data ahead of it has gone.
                _finSent = false;
            }

            progressed = true;
        }

        var sent = 0;

        while (sent < InboundQuantum && channel.TryRead(out var data))
        {
            if (!_sink.CanAccept)
            {
                // No room downstream. Leaving the bytes unreleased closes the channel's window,
                // which is how the far end is told to slow down.
                break;
            }

            // Bytes between the acknowledgement and _sendNext are in flight and still sit at the
            // front of the channel's buffer; what follows them has not been sent yet.
            var inFlight = (int)(_sendNext - _sendUnacknowledged);
            var unsent = data.Count - inFlight;

            if (unsent <= 0)
            {
                break;
            }

            // Never more in flight than the peer said it would buffer. Data beyond the advertised
            // window is not merely impolite - the peer drops it.
            var window = _peerWindow > (uint)inFlight ? _peerWindow - (uint)inFlight : 0;

            if (window == 0)
            {
                break;
            }

            var take = Math.Min(Math.Min(unsent, OurMaximumSegmentSize), (int)window);

            if (!SendSegment(TcpFlags.Ack | TcpFlags.Psh, data.AsSpan().Slice(inFlight, take)))
            {
                break;
            }

            if (_sendNext == _sendUnacknowledged)
            {
                // The clock starts when the wire goes quiet-to-busy, not per segment.
                _retransmitAt = _clock.Now + _retransmitInterval;
            }

            _sendNext += (uint)take;

            sent++;
            progressed = true;
        }

        if (channel.IsPeerEof && _state is TcpState.Established or TcpState.CloseWait)
        {
            // Whichever side finished first, this is us finishing. From Established the peer may
            // still be sending, so we half-close and wait for its FIN; from CloseWait it already
            // sent one, so the only thing left is the acknowledgement of ours. Handling just the
            // Established case - which is what this did - left every gracefully closed connection
            // parked in CloseWait for the life of the tunnel, holding its channel. The FIN itself
            // goes below, once nothing is left ahead of it.
            _state = _state == TcpState.Established ? TcpState.FinWait : TcpState.LastAck;
            progressed = true;
        }

        if (!_finSent && _state is TcpState.FinWait or TcpState.LastAck)
        {
            // A FIN takes its place in the sequence space after the data, so it waits until every
            // buffered byte has at least been sent. Separate from the transition above because a
            // retransmission rewind un-sends it, and this is also where it goes again.
            var buffered = channel.TryRead(out var remaining) ? remaining.Count : 0;

            if (buffered <= (int)(_sendNext - _sendUnacknowledged))
            {
                if (_sendNext == _sendUnacknowledged)
                {
                    _retransmitAt = _clock.Now + _retransmitInterval;
                }

                SendSegment(TcpFlags.Fin | TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
                _sendNext++;
                _finSent = true;
                progressed = true;
            }
        }

        return progressed;
    }

    /// <summary>Discards the flow without ceremony.</summary>
    public void Abort()
    {
        Finish();
    }

    /// <summary>
    /// Marks the flow finished and releases its channel.
    /// </summary>
    /// <remarks>
    /// The channel has to go here rather than when the loop drops the flow: the loop only forgets
    /// the entry, so a flow that closed without releasing it would leave the channel open on the
    /// server and subscribed to the session for as long as the tunnel lasts.
    /// </remarks>
    private void Finish()
    {
        _state = TcpState.Closed;
        _channel?.Dispose();
        _channel = null;
    }

    /// <summary>
    /// Passes payload to the channel, and reports how much of it was taken.
    /// </summary>
    /// <remarks>
    /// Only what the channel accepted is acknowledged. Acknowledging the rest would promise delivery
    /// of bytes that were dropped, and the peer would never send them again - the connection would
    /// simply lose a piece of its stream. Leaving them unacknowledged makes the peer retransmit,
    /// which is exactly the mechanism TCP already has for this, so the stack needs no buffer of its
    /// own to hold them in.
    /// </remarks>
    private int DeliverToChannel(ReadOnlySpan<byte> payload)
    {
        var channel = _channel;
        if (channel is null)
        {
            return 0;
        }

        var buffer = payload.ToArray();
        var result = channel.TrySend(buffer, 0, buffer.Length, out var written);

        if (result == ByteChannelSendResult.Closed)
        {
            return 0;
        }

        _receiveNext += (uint)written;
        return written;
    }

    private void SendChannelEof()
    {
        if (_channelEofSent)
        {
            return;
        }

        _channelEofSent = true;
        _channel?.SendEof();
    }

    /// <summary>
    /// Notes that an acknowledgement is owed, to be sent shortly unless something carries it sooner.
    /// </summary>
    /// <remarks>
    /// A second segment arriving while one is already owed is acknowledged at once, which is what
    /// every implementation does and what keeps a bulk transfer from waiting out the delay on every
    /// other segment.
    /// </remarks>
    private void ScheduleAck()
    {
        if (_ackDue)
        {
            SendAck();
            return;
        }

        _ackDue = true;
        _ackDueAt = _clock.Now + AckDelay;
    }

    private void SendAck()
    {
        _ackDue = false;
        _ = SendSegment(TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
    }

    private bool SendSegment(TcpFlags flags, ReadOnlySpan<byte> payload, ushort? mss = null)
    {
        // Every segment carries the acknowledgement number, so anything we send settles the debt.
        _ackDue = false;

        var tcpStart = Ipv4Packet.MinimumHeaderLength;
        var headerLength = TcpSegment.MinimumHeaderLength + (mss.HasValue ? 4 : 0);

        payload.CopyTo(_scratch.AsSpan(tcpStart + headerLength));

        // Reversed: what the operating system sent to the far end now comes back from it.
        var tcpLength = TcpSegment.Write(
            _scratch.AsSpan(tcpStart),
            _key.RemoteAddress,
            _key.LocalAddress,
            _key.RemotePort,
            _key.LocalPort,
            _sendNext,
            _receiveNext,
            flags,
            ReceiveWindow,
            payload.Length,
            mss);

        var total = Ipv4Packet.Write(_scratch, IpProtocol.Tcp, _key.RemoteAddress, _key.LocalAddress, tcpLength);
        return _sink.TryWrite(_scratch.AsSpan(0, total));
    }

    /// <summary>
    /// Answers a segment on a flow we know nothing about.
    /// </summary>
    private void SendReset(in TcpSegment tcp)
    {
        _sendNext = tcp.AcknowledgementNumber;
        _receiveNext = tcp.SequenceNumber + (uint)tcp.Payload.Length;
        _ = SendSegment(TcpFlags.Rst | TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
        _state = TcpState.Closed;
    }

    /// <summary>
    /// Picks an initial send sequence number.
    /// </summary>
    /// <remarks>
    /// Derived from the four-tuple rather than random. Nothing here is exposed to an off-path
    /// attacker - both ends of this connection are inside the tunnel - and a deterministic choice
    /// makes the tests readable. A real internet-facing stack would not do this.
    /// </remarks>
    private static uint InitialSendSequence(TcpFlowKey key)
    {
        var hash = (uint)HashCode.Combine(key.LocalAddress, key.LocalPort, key.RemoteAddress, key.RemotePort);
        return hash & 0x7FFFFFFF;
    }
}
