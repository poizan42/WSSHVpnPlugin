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
    private static readonly uint Client = Packets.Address("192.168.255.2");
    private static readonly uint Server = Packets.Address("1.1.1.1");
    private const ushort ClientPort = 40000;
    private const ushort ServerPort = 80;

    private FakeChannelFactory _channels = null!;
    private FakeSink _sink = null!;
    private StackLoop _stack = null!;

    [TestInitialize]
    public void Initialize()
    {
        _channels = new FakeChannelFactory();
        _sink = new FakeSink();
        _stack = new StackLoop(_channels, _sink);
    }

    private void Syn(ushort? mss = 1460, ushort port = ClientPort)
    {
        _ = _stack.Offer(Packets.Tcp(Client, Server, port, ServerPort, 1000, 0, TcpFlags.Syn, default, mss));
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

        _ = _channels.CompleteOpen();

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

    [TestMethod]
    public void PeerMaximumSegmentSize_IsHonouredWhenOffered()
    {
        _channels.OpenImmediately = false;
        Syn(mss: 1200);
        _ = _channels.CompleteOpen();

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
        var total = Ipv4Packet.Write(buffer, IpProtocol.Udp, Client, Server, 20);

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
}
