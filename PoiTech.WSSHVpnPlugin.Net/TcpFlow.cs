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

    private IByteChannel? _channel;
    private TcpState _state;
    private uint _sendNext;
    private uint _receiveNext;
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

            if (_state == TcpState.Established)
            {
                _state = TcpState.CloseWait;
            }

            // A FIN is acknowledged at once: nothing more is coming to piggyback on.
            SendAck();
            SendChannelEof();
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

        while (channel.TryRead(out var data))
        {
            if (!_sink.CanAccept)
            {
                // No room downstream. Leaving the bytes unreleased closes the channel's window,
                // which is how the far end is told to slow down.
                break;
            }

            var take = Math.Min(data.Count, OurMaximumSegmentSize);

            if (!SendSegment(TcpFlags.Ack | TcpFlags.Psh, data.AsSpan()[..take]))
            {
                break;
            }

            _sendNext += (uint)take;

            if (channel.Advance(take))
            {
                channel.FlushWindowCredit();
            }

            progressed = true;
        }

        if (channel.IsPeerEof && _state == TcpState.Established)
        {
            _state = TcpState.FinWait;
            SendSegment(TcpFlags.Fin | TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
            _sendNext++;
            progressed = true;
        }

        return progressed;
    }

    /// <summary>Discards the flow without ceremony.</summary>
    public void Abort()
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
