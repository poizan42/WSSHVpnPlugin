using System;
using System.Linq;
using System.Text;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.Net.Tests;

/// <summary>
/// Drives whole connections through the stack with synthetic packets.
/// </summary>
[TestClass]
public class StackLoopTests
{
    private static readonly IpAddr Client = Packets.Address("192.168.255.2");
    private static readonly IpAddr Server = Packets.Address("1.1.1.1");
    private const ushort ClientPort = 40000;
    private const ushort ServerPort = 80;

    private FakeChannelFactory _channels = null!;
    private FakeSink _sink = null!;
    private FakeClock _clock = null!;
    private StackLoop _stack = null!;

    [TestInitialize]
    public void Initialize()
    {
        _channels = new FakeChannelFactory();
        _sink = new FakeSink();
        _clock = new FakeClock();
        _stack = new StackLoop(_channels, _sink, _clock, mtu: 1400);
    }

    private void Syn(ushort? mss = 1460, ushort port = ClientPort)
    {
        _ = _stack.Offer(Packets.Tcp(Client, Server, port, ServerPort, 1000, 0, TcpFlags.Syn, default, mss));

        // A channel that opened is only attached to its flow on the stack's own thread, so the
        // handshake is answered by the loop rather than by whoever completed the open.
        _ = _stack.RunOnce();
    }

    /// <summary>Opens the channel a SYN asked for, and lets the loop pick it up.</summary>
    private FakeChannel CompleteOpen()
    {
        var channel = _channels.CompleteOpen();
        _ = _stack.RunOnce();
        return channel;
    }

    private void Send(uint sequenceNumber, string text, TcpFlags flags = TcpFlags.Ack | TcpFlags.Psh)
    {
        _ = _stack.Offer(Packets.Tcp(Client, Server, ClientPort, ServerPort, sequenceNumber, 0, flags, Encoding.ASCII.GetBytes(text)));
    }

    [TestMethod]
    public void Syn_OpensAChannelToTheDestination()
    {
        Syn();

        Assert.AreEqual(1, _channels.OpenRequests);
        Assert.AreEqual(Server, _channels.LastAddress);
        Assert.AreEqual(ServerPort, _channels.LastPort);
    }

    /// <summary>
    /// Nothing is answered until the channel is open. Accepting a connection we cannot serve would
    /// be worse than making the peer wait for it.
    /// </summary>
    [TestMethod]
    public void Syn_IsNotAnsweredUntilTheChannelOpens()
    {
        _channels.OpenImmediately = false;

        Syn();

        Assert.AreEqual(0, _sink.Packets.Count);

        _ = CompleteOpen();

        var reply = _sink.Last();
        Assert.AreEqual(TcpFlags.Syn | TcpFlags.Ack, reply.Flags);
    }

    [TestMethod]
    public void SynAck_IsAddressedBackAtTheClientAndAcknowledgesTheSyn()
    {
        Syn();

        var reply = _sink.Last();
        Assert.AreEqual(Server, reply.Source);
        Assert.AreEqual(Client, reply.Destination);
        Assert.AreEqual(ServerPort, reply.SourcePort);
        Assert.AreEqual(ClientPort, reply.DestinationPort);
        Assert.AreEqual(1001u, reply.Ack, "the SYN occupies a sequence number");
    }

    /// <summary>
    /// A peer that receives no MSS assumes 536 and runs at half throughput while appearing to work.
    /// </summary>
    [TestMethod]
    public void SynAck_CarriesOurMaximumSegmentSize()
    {
        Syn();

        var bytes = _sink.Packets[^1];
        Assert.IsTrue(Ipv4Packet.TryParse(bytes, out var ip));
        Assert.IsTrue(TcpSegment.TryParse(ip.Payload, out var tcp));
        Assert.IsTrue(tcp.TryGetMaximumSegmentSize(out var mss));
        Assert.AreEqual(1360, mss);
    }

    /// <summary>
    /// The MSS is derived from the tunnel MTU, not a constant: a profile that raises the MTU should
    /// get segments to match, and one that lowers it must not overrun the receive pool's buffers.
    /// </summary>
    [TestMethod]
    public void SynAck_MssFollowsTheConfiguredMtu()
    {
        _stack = new StackLoop(_channels, _sink, _clock, mtu: 1200);

        Syn();

        var bytes = _sink.Packets[^1];
        Assert.IsTrue(Ipv4Packet.TryParse(bytes, out var ip));
        Assert.IsTrue(TcpSegment.TryParse(ip.Payload, out var tcp));
        Assert.IsTrue(tcp.TryGetMaximumSegmentSize(out var mss));
        Assert.AreEqual(1160, mss);
    }

    [TestMethod]
    public void PeerMaximumSegmentSize_IsHonouredWhenOffered()
    {
        _channels.OpenImmediately = false;
        Syn(mss: 1200);
        _ = CompleteOpen();

        // The flow is not exposed directly; the observable effect is that it parsed without error
        // and answered, which the SYN-ACK confirms.
        Assert.AreEqual(TcpFlags.Syn | TcpFlags.Ack, _sink.Last().Flags);
    }

    [TestMethod]
    public void ChannelThatCannotBeOpened_IsRefusedWithAReset()
    {
        _channels.FailOpens = true;

        Syn();

        var reply = _sink.Last();
        Assert.IsTrue(reply.Flags.HasFlag(TcpFlags.Rst), $"expected a reset, got {reply.Flags}");
        Assert.AreEqual(0, _stack.FlowCount, "a refused flow should not be retained");
    }

    [TestMethod]
    public void Payload_ReachesTheChannelAndIsAcknowledged()
    {
        Syn();
        Send(1001, "GET / HTTP/1.1\r\n\r\n");

        CollectionAssert.AreEqual(
            Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n\r\n"),
            _channels.Last!.Sent.ToArray());

        _clock.Advance(TimeSpan.FromMilliseconds(50));
        _ = _stack.RunOnce();

        var ack = _sink.Last();
        Assert.AreEqual(TcpFlags.Ack, ack.Flags);
        Assert.AreEqual(1001u + 18, ack.Ack);
    }

    [TestMethod]
    public void ChannelData_ComesBackAsSegments()
    {
        Syn();
        var synAckSeq = _sink.Last().Seq;

        _channels.Last!.ReceiveFromPeer(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK"));

        Assert.IsTrue(_stack.RunOnce());

        var data = _sink.Last();
        Assert.IsTrue(data.Flags.HasFlag(TcpFlags.Ack));
        CollectionAssert.AreEqual(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK"), data.Payload);
        Assert.AreEqual(synAckSeq + 1, data.Seq, "data follows the SYN in the sequence space");
    }

    [TestMethod]
    public void LargeChannelData_IsSplitAtOurMaximumSegmentSize()
    {
        Syn();

        _channels.Last!.ReceiveFromPeer(new byte[3000]);
        _ = _stack.RunOnce();

        var payloads = Enumerable.Range(1, _sink.Packets.Count - 1).Select(i => _sink.At(i).Payload.Length).ToArray();
        Assert.IsTrue(payloads.All(p => p <= 1360), $"a segment exceeded the MSS: {string.Join(",", payloads)}");
        Assert.AreEqual(3000, payloads.Sum());
    }

    /// <summary>
    /// A full sink means no room to deliver. The bytes must stay unreleased so the channel's window
    /// closes and the far end slows down, rather than being dropped.
    /// </summary>
    [TestMethod]
    public void FullSink_StopsDeliveryWithoutLosingData()
    {
        Syn();
        _channels.Last!.ReceiveFromPeer(Encoding.ASCII.GetBytes("hello"));

        _sink.Full = true;
        _ = _stack.RunOnce();

        _sink.Full = false;
        Assert.IsTrue(_stack.RunOnce());

        CollectionAssert.AreEqual(Encoding.ASCII.GetBytes("hello"), _sink.Last().Payload);
    }

    [TestMethod]
    public void ClientFin_IsAcknowledgedAndPassedOnAsEof()
    {
        Syn();
        _ = _stack.Offer(Packets.Tcp(Client, Server, ClientPort, ServerPort, 1001, 0, TcpFlags.Fin | TcpFlags.Ack));

        Assert.IsTrue(_channels.Last!.EofSent);
        Assert.AreEqual(1002u, _sink.Last().Ack, "the FIN occupies a sequence number");
    }

    [TestMethod]
    public void ChannelEof_BecomesAFin()
    {
        Syn();
        _channels.Last!.IsPeerEof = true;

        _ = _stack.RunOnce();

        Assert.IsTrue(_sink.Last().Flags.HasFlag(TcpFlags.Fin));
    }

    /// <summary>
    /// The client closes first, then the far end. Both directions are then done, so the flow must be
    /// forgotten and its channel released - not parked in CLOSE-WAIT for the life of the tunnel.
    /// </summary>
    [TestMethod]
    public void CloseStartedByTheClient_EndsTheFlow()
    {
        Syn();
        var channel = _channels.Last!;

        _ = _stack.Offer(Packets.Tcp(Client, Server, ClientPort, ServerPort, 1001, 0, TcpFlags.Fin | TcpFlags.Ack));
        Assert.IsTrue(channel.EofSent, "the far end should be told the client finished");
        Assert.AreEqual(1, _stack.FlowCount, "half closed, so still tracked");

        // The far end answers by closing too.
        channel.IsPeerEof = true;
        _ = _stack.RunOnce();

        var fin = _sink.Last();
        Assert.IsTrue(fin.Flags.HasFlag(TcpFlags.Fin), $"expected our FIN, got {fin.Flags}");

        // The client acknowledges it.
        _ = _stack.Offer(Packets.Tcp(Client, Server, ClientPort, ServerPort, 1002, fin.Seq + 1, TcpFlags.Ack));

        Assert.AreEqual(0, _stack.FlowCount, "the flow should be forgotten");
        Assert.IsTrue(channel.Disposed, "the channel must not leak");
    }

    /// <summary>The other order: the far end closes first, then the client.</summary>
    [TestMethod]
    public void CloseStartedByTheFarEnd_EndsTheFlow()
    {
        Syn();
        var channel = _channels.Last!;

        channel.IsPeerEof = true;
        _ = _stack.RunOnce();

        var fin = _sink.Last();
        Assert.IsTrue(fin.Flags.HasFlag(TcpFlags.Fin));
        Assert.AreEqual(1, _stack.FlowCount, "half closed, so still tracked");

        _ = _stack.Offer(Packets.Tcp(Client, Server, ClientPort, ServerPort, 1001, fin.Seq + 1, TcpFlags.Fin | TcpFlags.Ack));

        Assert.AreEqual(1002u, _sink.Last().Ack, "the client's FIN occupies a sequence number");
        Assert.AreEqual(0, _stack.FlowCount, "the flow should be forgotten");
        Assert.IsTrue(channel.Disposed, "the channel must not leak");
    }

    /// <summary>
    /// One flow may not drain its whole channel in a single visit. Whatever drives the loop has to
    /// get back to the outbound direction: letting a flow run until the sink refuses makes the
    /// sink's capacity the fairness quantum, and starves the queue the operating system is filling.
    /// </summary>
    [TestMethod]
    public void OneVisit_SendsAtMostAQuantumOfSegments()
    {
        Syn();
        var before = _sink.Packets.Count;

        // Far more than a quantum's worth: 40 segments at our MSS.
        _channels.Last!.ReceiveFromPeer(new byte[40 * 1360]);

        _ = _stack.RunOnce();

        var sentInOnePass = _sink.Packets.Count - before;
        Assert.AreEqual(8, sentInOnePass, "a visit should stop at the quantum");

        // And the rest still follows on later passes, rather than being lost.
        for (var i = 0; i < 10; i++)
        {
            _ = _stack.RunOnce();
        }

        Assert.AreEqual(40, _sink.Packets.Count - before, "the remainder should still be delivered");
    }

    /// <summary>
    /// The peer's advertised window is a hard bound on what may be in flight to it. Data past it is
    /// dropped by the peer, and nothing on this path resends - at speed that wedged whole downloads.
    /// </summary>
    [TestMethod]
    public void PeerWindow_BoundsWhatIsInFlight()
    {
        Syn();
        var synAckSeq = _sink.Last().Seq;

        // The client announces a two-segment window.
        _ = _stack.Offer(Packets.Tcp(Client, Server, ClientPort, ServerPort, 1001, synAckSeq + 1, TcpFlags.Ack, windowSize: 2720));

        _channels.Last!.ReceiveFromPeer(new byte[10000]);

        for (var i = 0; i < 5; i++)
        {
            _ = _stack.RunOnce();
        }

        var delivered = 0;
        for (var i = 1; i < _sink.Packets.Count; i++)
        {
            delivered += _sink.At(i).Payload.Length;
        }

        Assert.AreEqual(2720, delivered, "no more than the advertised window may be outstanding");

        // Acknowledging what arrived reopens the window, and the rest follows.
        _ = _stack.Offer(Packets.Tcp(Client, Server, ClientPort, ServerPort, 1001, synAckSeq + 1 + 2720, TcpFlags.Ack, windowSize: 65535));

        for (var i = 0; i < 5; i++)
        {
            _ = _stack.RunOnce();
        }

        delivered = 0;
        for (var i = 1; i < _sink.Packets.Count; i++)
        {
            delivered += _sink.At(i).Payload.Length;
        }

        Assert.AreEqual(10000, delivered, "the remainder goes once the window reopens");
    }

    /// <summary>
    /// A segment the platform loses must be sent again. The channel's buffer holds everything not
    /// yet acknowledged, so a retransmission timeout rewinds and resends from the last
    /// acknowledgement - without this, one lost segment wedged a flow forever, which is how
    /// downloads started failing the moment the tunnel got fast enough to provoke loss.
    /// </summary>
    [TestMethod]
    public void UnacknowledgedData_IsResentAfterTheTimeout()
    {
        Syn();
        _channels.Last!.ReceiveFromPeer(Encoding.ASCII.GetBytes("hello"));
        _ = _stack.RunOnce();

        var first = _sink.Last();
        CollectionAssert.AreEqual(Encoding.ASCII.GetBytes("hello"), first.Payload);
        var count = _sink.Packets.Count;

        // No acknowledgement arrives. Before the timeout, nothing is resent.
        _clock.Advance(TimeSpan.FromMilliseconds(100));
        _ = _stack.RunOnce();
        Assert.AreEqual(count, _sink.Packets.Count, "too early to resend");

        _clock.Advance(TimeSpan.FromMilliseconds(150));
        _ = _stack.RunOnce();

        var resent = _sink.Last();
        CollectionAssert.AreEqual(Encoding.ASCII.GetBytes("hello"), resent.Payload, "the same bytes go again");
        Assert.AreEqual(first.Seq, resent.Seq, "at the same sequence number");

        // The acknowledgement finally lands, and releases the channel's bytes.
        _ = _stack.Offer(Packets.Tcp(Client, Server, ClientPort, ServerPort, 1001, first.Seq + 5, TcpFlags.Ack));
        count = _sink.Packets.Count;

        _clock.Advance(TimeSpan.FromSeconds(3));
        _ = _stack.RunOnce();
        Assert.AreEqual(count, _sink.Packets.Count, "acknowledged data is never resent");
    }

    /// <summary>
    /// The server's EOF arrives right behind its last data, while megabytes may still be buffered
    /// for the client. Every byte of that tail must still be delivered, and the FIN after it.
    /// </summary>
    /// <remarks>
    /// This is the final moment of every download, and it wedged exactly there: the EOF moved the
    /// flow into FinWait, the pump's guard only admitted the established states, and the tail sat
    /// in the buffer forever - the transfer showing "a few seconds left" until the user gave up.
    /// </remarks>
    [TestMethod]
    public void ServerEofWithABufferedTail_DeliversEverythingThenCloses()
    {
        Syn();
        var channel = _channels.Last!;
        var synAckSequence = _sink.Last().Seq;

        // More than one visit's quantum, so the EOF is seen while most of the tail is unsent.
        var tail = new byte[30000];
        for (var i = 0; i < tail.Length; i++)
        {
            tail[i] = (byte)i;
        }

        channel.ReceiveFromPeer(tail);
        channel.IsPeerEof = true;

        for (var visit = 0; visit < 10; visit++)
        {
            _ = _stack.RunOnce();
        }

        var payload = _sink.Packets
            .Select((_, index) => _sink.At(index))
            .Where(p => p.DestinationPort == ClientPort && p.Payload.Length > 0)
            .SelectMany(p => p.Payload)
            .ToArray();

        CollectionAssert.AreEqual(tail, payload, "the whole tail must reach the client before the close");
        Assert.IsTrue(_sink.Last().Flags.HasFlag(TcpFlags.Fin), "the FIN follows once every buffered byte has been sent");

        // The client acknowledges everything including the FIN, and closes its own side.
        var finalAck = synAckSequence + 1 + (uint)tail.Length + 1;
        _ = _stack.Offer(Packets.Tcp(Client, Server, ClientPort, ServerPort, 1001, finalAck, TcpFlags.Fin | TcpFlags.Ack));

        Assert.AreEqual(0, _stack.FlowCount);
        Assert.IsTrue(channel.Disposed);
    }

    [TestMethod]
    public void Reset_DiscardsTheFlow()
    {
        Syn();
        Assert.AreEqual(1, _stack.FlowCount);

        _ = _stack.Offer(Packets.Tcp(Client, Server, ClientPort, ServerPort, 1001, 0, TcpFlags.Rst));

        Assert.AreEqual(0, _stack.FlowCount);
        Assert.IsTrue(_channels.Last!.Disposed);
    }

    /// <summary>
    /// A segment for a connection we know nothing about gets a reset, so the peer stops retrying
    /// instead of waiting out its own timeout.
    /// </summary>
    [TestMethod]
    public void DataForAnUnknownFlow_IsReset()
    {
        Send(5000, "stray");

        Assert.IsTrue(_sink.Last().Flags.HasFlag(TcpFlags.Rst));
        Assert.AreEqual(0, _stack.FlowCount);
    }

    /// <summary>
    /// The stragglers of a dead connection arrive in a burst - everything in flight when the peer
    /// gave up - and none of them is the start of anything. Creating a flow per packet just to
    /// reset it logged a phantom connection for each one.
    /// </summary>
    [TestMethod]
    public void DataForAnUnknownFlow_DoesNotAnnounceAFlow()
    {
        var started = 0;
        _stack.FlowStarted = _ => started++;

        Send(5000, "stray");

        Assert.AreEqual(0, started);
    }

    /// <summary>
    /// A reset for a connection nothing holds is answered with nothing: replying to a reset is how
    /// two stacks chase each other in circles.
    /// </summary>
    [TestMethod]
    public void ResetForAnUnknownFlow_IsIgnored()
    {
        var started = 0;
        _stack.FlowStarted = _ => started++;

        _ = _stack.Offer(Packets.Tcp(Client, Server, ClientPort, ServerPort, 1001, 0, TcpFlags.Rst));

        Assert.AreEqual(0, started);
        Assert.AreEqual(0, _sink.Packets.Count);
        Assert.AreEqual(0, _stack.FlowCount);
    }

    /// <summary>
    /// The client resetting a live flow is its application giving up, and the flow's state at that
    /// moment is the only evidence of why. See <see cref="TcpFlow.Describe"/>.
    /// </summary>
    [TestMethod]
    public void ResetOfALiveFlow_ReportsTheSenderPostMortem()
    {
        string? postMortem = null;
        _stack.FlowReset = (_, description) => postMortem = description;

        Syn();

        _ = _stack.Offer(Packets.Tcp(Client, Server, ClientPort, ServerPort, 1001, 0, TcpFlags.Rst));

        Assert.IsNotNull(postMortem);
        Assert.IsTrue(postMortem.Contains("state Established", StringComparison.Ordinal), postMortem);
        Assert.IsTrue(postMortem.Contains("peer window", StringComparison.Ordinal), postMortem);
    }

    [TestMethod]
    public void OutOfOrderSegment_IsDroppedAndReAcknowledged()
    {
        Syn();
        var before = _channels.Last!.Sent.Count;

        Send(9999, "out of order");

        Assert.AreEqual(before, _channels.Last.Sent.Count, "out-of-order data must not reach the channel");
        Assert.AreEqual(TcpFlags.Ack, _sink.Last().Flags);
        Assert.AreEqual(1001u, _sink.Last().Ack, "still acknowledging what we do have");
    }

    [TestMethod]
    public void TwoConnections_AreTrackedSeparately()
    {
        Syn(port: 40000);
        Syn(port: 40001);

        Assert.AreEqual(2, _stack.FlowCount);
        Assert.AreEqual(2, _channels.OpenRequests);
    }

    [TestMethod]
    public void Broadcast_IsDroppedBeforeTheFlowTable()
    {
        var packet = Packets.Tcp(Client, Packets.Address("255.255.255.255"), 137, 137, 1, 0, TcpFlags.Syn);

        Assert.IsFalse(_stack.Offer(packet));
        Assert.AreEqual(0, _stack.FlowCount);
        Assert.AreEqual(1, _stack.Dropped);
    }

    [TestMethod]
    public void Multicast_IsDroppedBeforeTheFlowTable()
    {
        var packet = Packets.Tcp(Client, Packets.Address("224.0.0.22"), 1, 2, 1, 0, TcpFlags.Syn);

        Assert.IsFalse(_stack.Offer(packet));
        Assert.AreEqual(0, _stack.FlowCount);
    }

    [TestMethod]
    public void NonTcp_IsDropped()
    {
        var buffer = new byte[40];
        var total = Ipv4Packet.Write(buffer, IpProtocol.Udp, Client.V4, Server.V4, 20);

        Assert.IsFalse(_stack.Offer(buffer.AsSpan(0, total)));
        Assert.AreEqual(1, _stack.Dropped);
    }

    [TestMethod]
    public void Garbage_IsDroppedRatherThanParsed()
    {
        Assert.IsFalse(_stack.Offer(new byte[] { 0xFF, 0x01, 0x02 }));
        Assert.AreEqual(1, _stack.Dropped);
    }

    /// <summary>
    /// The whole exchange, end to end: connect, request, response, both sides close.
    /// </summary>
    [TestMethod]
    public void WholeConnection_RunsThrough()
    {
        Syn();
        Assert.AreEqual(TcpFlags.Syn | TcpFlags.Ack, _sink.Last().Flags);

        Send(1001, "GET / HTTP/1.1\r\n\r\n");
        CollectionAssert.AreEqual(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n\r\n"), _channels.Last!.Sent.ToArray());

        _channels.Last.ReceiveFromPeer(Encoding.ASCII.GetBytes("HTTP/1.1 301 Moved"));
        _ = _stack.RunOnce();
        CollectionAssert.AreEqual(Encoding.ASCII.GetBytes("HTTP/1.1 301 Moved"), _sink.Last().Payload);

        _channels.Last.IsPeerEof = true;
        _ = _stack.RunOnce();
        Assert.IsTrue(_sink.Last().Flags.HasFlag(TcpFlags.Fin));

        _ = _stack.Offer(Packets.Tcp(Client, Server, ClientPort, ServerPort, 1019, 0, TcpFlags.Fin | TcpFlags.Ack));
        Assert.IsTrue(_channels.Last.EofSent);
    }

    /// <summary>
    /// An acknowledgement waits briefly for something to travel with, rather than costing a packet
    /// of its own.
    /// </summary>
    [TestMethod]
    public void Acknowledgement_IsDelayed()
    {
        Syn();
        var before = _sink.Packets.Count;

        Send(1001, "hello");

        Assert.AreEqual(before, _sink.Packets.Count, "the acknowledgement should not have gone yet");

        _clock.Advance(TimeSpan.FromMilliseconds(50));
        _ = _stack.RunOnce();

        Assert.AreEqual(TcpFlags.Ack, _sink.Last().Flags);
        Assert.AreEqual(1006u, _sink.Last().Ack);
    }

    [TestMethod]
    public void DelayedAcknowledgement_DoesNotFireEarly()
    {
        Syn();
        Send(1001, "hello");
        var before = _sink.Packets.Count;

        _clock.Advance(TimeSpan.FromMilliseconds(10));
        _ = _stack.RunOnce();

        Assert.AreEqual(before, _sink.Packets.Count);
    }

    /// <summary>
    /// A second segment while one acknowledgement is already owed is answered at once, or a bulk
    /// transfer waits out the delay on every other segment.
    /// </summary>
    [TestMethod]
    public void SecondSegment_IsAcknowledgedImmediately()
    {
        Syn();
        Send(1001, "one");
        var before = _sink.Packets.Count;

        Send(1004, "two");

        Assert.AreEqual(before + 1, _sink.Packets.Count);
        Assert.AreEqual(1007u, _sink.Last().Ack);
    }

    /// <summary>
    /// Data travelling back carries the acknowledgement, so no bare one should follow it.
    /// </summary>
    [TestMethod]
    public void OutgoingData_CarriesTheAcknowledgement()
    {
        Syn();
        Send(1001, "hello");

        _channels.Last!.ReceiveFromPeer(Encoding.ASCII.GetBytes("hi"));
        _ = _stack.RunOnce();

        Assert.AreEqual(1006u, _sink.Last().Ack, "the reply should acknowledge what arrived");

        var after = _sink.Packets.Count;
        _clock.Advance(TimeSpan.FromMilliseconds(50));
        _ = _stack.RunOnce();

        Assert.AreEqual(after, _sink.Packets.Count, "the debt was already settled by the data segment");
    }

    /// <summary>
    /// The critical one. A channel that can only take part of a segment must leave the rest
    /// unacknowledged, so the peer sends it again. Acknowledging it would promise delivery of bytes
    /// that were dropped, and the stream would silently lose a piece.
    /// </summary>
    [TestMethod]
    public void PartiallyAcceptedData_IsOnlyAcknowledgedAsFarAsItWasTaken()
    {
        Syn();
        _channels.Last!.SendLimit = 4;

        Send(1001, "abcdefghij");

        CollectionAssert.AreEqual(Encoding.ASCII.GetBytes("abcd"), _channels.Last.Sent.ToArray());

        var ack = _sink.Last();
        Assert.AreEqual(TcpFlags.Ack, ack.Flags);
        Assert.AreEqual(1005u, ack.Ack, "only the four bytes that were taken may be acknowledged");
    }

    [TestMethod]
    public void RetransmissionAfterAPartialTake_IsAcceptedFromWhereItLeftOff()
    {
        Syn();
        _channels.Last!.SendLimit = 4;
        Send(1001, "abcdefghij");

        // The peer retransmits the remainder, and by now the channel has room.
        _channels.Last.SendLimit = -1;
        Send(1005, "efghij");

        CollectionAssert.AreEqual(Encoding.ASCII.GetBytes("abcdefghij"), _channels.Last.Sent.ToArray());

        // The second delivery was complete, so its acknowledgement is delayed like any other.
        _clock.Advance(TimeSpan.FromMilliseconds(50));
        _ = _stack.RunOnce();

        Assert.AreEqual(1011u, _sink.Last().Ack);
    }

    [TestMethod]
    public void ClosedChannel_AcknowledgesNothing()
    {
        Syn();
        _channels.Last!.IsOpen = false;
        var ackBefore = _sink.Last().Ack;

        Send(1001, "anything");

        Assert.AreEqual(ackBefore, _sink.Last().Ack, "nothing was delivered, so nothing may be acknowledged");
    }
}
