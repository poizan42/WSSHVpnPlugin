using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.Net.Tests;

/// <summary>
/// Drives IPv6 connections through the stack, mirroring the load-bearing IPv4 cases.
/// </summary>
[TestClass]
public class Ipv6StackTests
{
    private static readonly IpAddr Client = Packets.Address("fd00::2");
    private static readonly IpAddr Server = Packets.Address("2001:db8::1");
    private const ushort ClientPort = 40000;
    private const ushort ServerPort = 443;

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

    private void Syn(ushort? mss = 1440)
    {
        _ = _stack.Offer(Packets.Tcp(Client, Server, ClientPort, ServerPort, 1000, 0, TcpFlags.Syn, default, mss));
        _ = _stack.RunOnce();
    }

    private void Send(uint sequenceNumber, string text)
    {
        _ = _stack.Offer(Packets.Tcp(
            Client, Server, ClientPort, ServerPort, sequenceNumber, 0,
            TcpFlags.Ack | TcpFlags.Psh, Encoding.ASCII.GetBytes(text)));
    }

    /// <summary>Parses the sink's last packet as IPv6 TCP and verifies the checksum on the way.</summary>
    private (Ipv6View Ip, uint Seq, uint Ack, TcpFlags Flags, ushort? Mss, byte[] Payload) LastV6()
    {
        var bytes = _sink.Packets[^1];

        Assert.IsTrue(Ipv6Packet.TryParse(bytes, out var ip), "the reply must be an IPv6 packet");
        Assert.AreEqual(IpProtocol.Tcp, ip.NextHeader);
        Assert.IsTrue(TcpSegment.TryParse(ip.Payload, out var tcp));
        Assert.IsTrue(tcp.IsChecksumValid(ip.Source, ip.Destination), "the v6 TCP checksum must verify");

        ushort? mss = tcp.TryGetMaximumSegmentSize(out var value) ? value : null;
        var view = new Ipv6View(ip.Source, ip.Destination, bytes.Length);
        return (view, tcp.SequenceNumber, tcp.AcknowledgementNumber, tcp.Flags, mss, tcp.Payload.ToArray());
    }

    private readonly record struct Ipv6View(IpAddr Source, IpAddr Destination, int TotalLength);

    [TestMethod]
    public void V6Syn_OpensAChannelToTheDestination()
    {
        Syn();

        Assert.AreEqual(1, _channels.OpenRequests);
        Assert.AreEqual(Server, _channels.LastAddress);
        Assert.AreEqual(ServerPort, _channels.LastPort);
    }

    [TestMethod]
    public void V6SynAck_IsAddressedBack_WithMss1340_AndAValidChecksum()
    {
        Syn();

        var reply = LastV6();
        Assert.AreEqual(TcpFlags.Syn | TcpFlags.Ack, reply.Flags);
        Assert.AreEqual(Server, reply.Ip.Source);
        Assert.AreEqual(Client, reply.Ip.Destination);
        Assert.AreEqual(1001u, reply.Ack, "the SYN occupies a sequence number");
        Assert.AreEqual((ushort)1340, reply.Mss, "1400 less the IPv6 and TCP headers");
    }

    [TestMethod]
    public void V6Payload_ReachesTheChannel_AndDataComesBackAsV6()
    {
        Syn();
        var synAckSeq = LastV6().Seq;

        Send(1001, "GET /");
        _clock.Advance(TimeSpan.FromMilliseconds(50));
        _ = _stack.RunOnce();

        CollectionAssert.AreEqual(Encoding.ASCII.GetBytes("GET /"), _channels.Last!.Sent);

        _channels.Last.ReceiveFromPeer(Encoding.ASCII.GetBytes("200 OK"));
        _ = _stack.RunOnce();

        var reply = LastV6();
        CollectionAssert.AreEqual(Encoding.ASCII.GetBytes("200 OK"), reply.Payload);
        Assert.AreEqual(synAckSeq + 1, reply.Seq);
    }

    [TestMethod]
    public void V6GracefulClose_FinishesTheFlow()
    {
        Syn();

        _channels.Last!.IsPeerEof = true;
        _ = _stack.RunOnce();

        var fin = LastV6();
        Assert.IsTrue(fin.Flags.HasFlag(TcpFlags.Fin), $"expected a FIN, got {fin.Flags}");

        _ = _stack.Offer(Packets.Tcp(
            Client, Server, ClientPort, ServerPort, 1001, fin.Seq + 1, TcpFlags.Ack | TcpFlags.Fin));
        _ = _stack.RunOnce();

        Assert.AreEqual(0, _stack.FlowCount, "both directions closed; the flow should be gone");
    }

    /// <summary>
    /// A straggler of a dead connection gets its reset without a flow, exactly like v4 - and the
    /// reset is a well-formed 60-byte v6 packet.
    /// </summary>
    [TestMethod]
    public void V6Straggler_GetsAWellFormedReset()
    {
        _ = _stack.Offer(Packets.Tcp(Client, Server, ClientPort, ServerPort, 5000, 6000, TcpFlags.Ack));

        var reply = LastV6();
        Assert.IsTrue(reply.Flags.HasFlag(TcpFlags.Rst), $"expected a reset, got {reply.Flags}");
        Assert.AreEqual(Ipv6Packet.HeaderLength + TcpSegment.MinimumHeaderLength, reply.Ip.TotalLength);
        Assert.AreEqual(0, _stack.FlowCount);
    }

    private byte[] WithNextHeader(IpProtocol nextHeader, int payloadLength = 8)
    {
        var buffer = new byte[Ipv6Packet.HeaderLength + payloadLength];
        _ = Ipv6Packet.Write(buffer, nextHeader, Client, Server, payloadLength);
        return buffer;
    }

    [TestMethod]
    public void V6FragmentHeader_IsDroppedAndCounted()
    {
        Assert.IsFalse(_stack.Offer(WithNextHeader(IpProtocol.Fragment)));
        Assert.AreEqual(1, _stack.DroppedV6);
        Assert.AreEqual(0, _stack.Dropped, "a v6 drop must not hide in the v4 counter");
    }

    [TestMethod]
    public void V6HopByHop_IsDroppedAndCounted()
    {
        Assert.IsFalse(_stack.Offer(WithNextHeader(IpProtocol.HopByHopOptions)));
        Assert.AreEqual(1, _stack.DroppedV6);
    }

    [TestMethod]
    public void V6NonUnicastDestinations_AreDroppedBeforeTheFlowTable()
    {
        foreach (var destination in new[] { "ff02::1:ff00:2", "fe80::1", "::" })
        {
            Assert.IsFalse(
                _stack.Offer(Packets.Tcp(Client, Packets.Address(destination), 1, 2, 1, 0, TcpFlags.Syn)),
                destination);
        }

        Assert.AreEqual(3, _stack.DroppedV6);
        Assert.AreEqual(0, _stack.FlowCount);
        Assert.AreEqual(0, _channels.OpenRequests);
    }

    /// <summary>
    /// ICMPv6 is dropped but never silently: the histogram counts every packet, and the callback
    /// fires once per type - including for a Neighbour Solicitation, which arrives on solicited-node
    /// multicast and must still be seen.
    /// </summary>
    [TestMethod]
    public void IcmpV6_IsCountedAndReportedOncePerType_NotAnswered()
    {
        var seen = new List<(byte Type, byte Code)>();
        _stack.IcmpV6Seen = (type, code, _, _) => seen.Add((type, code));

        var solicitation = new byte[Ipv6Packet.HeaderLength + 24];
        _ = Ipv6Packet.Write(solicitation, IpProtocol.IcmpV6, Client, Packets.Address("ff02::1:ff00:2"), 24);
        solicitation[Ipv6Packet.HeaderLength] = 135;

        Assert.IsFalse(_stack.Offer(solicitation));
        Assert.IsFalse(_stack.Offer(solicitation));

        Assert.AreEqual(2, _stack.DroppedV6);
        Assert.AreEqual(0, _sink.Packets.Count, "nothing may be answered");
        Assert.AreEqual(1, seen.Count, "the callback fires once per type");
        Assert.AreEqual((byte)135, seen[0].Type);
        StringAssert.Contains(_stack.DescribeIcmpV6(), "135:2");
    }

    /// <summary>
    /// A v6 client querying a v6 resolver rides the same RFC 7766 relay: the query goes out framed
    /// on a channel to the server, and the reply comes back as a v6 datagram with a valid checksum.
    /// </summary>
    [TestMethod]
    public void V6DnsQuery_IsRelayed_AndAnsweredAsAV6Datagram()
    {
        var query = BuildDnsQuery();
        Assert.IsTrue(_stack.Offer(Packets.Udp(Client, Server, 50000, 53, query)));
        _ = _stack.RunOnce();

        Assert.AreEqual(Server, _channels.LastAddress);
        Assert.AreEqual((ushort)53, _channels.LastPort);

        // Read the relay's framed request back, echo it as the reply (a well-formed response with
        // the relay's own identifier), and frame it the way the server would.
        var sent = _channels.Last!.Sent.ToArray();
        var message = sent[2..];
        message[2] = 0x80;                                   // a response
        var framed = new byte[2 + message.Length];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)message.Length);
        message.CopyTo(framed, 2);
        _channels.Last.ReceiveFromPeer(framed);
        _ = _stack.RunOnce();

        Assert.AreEqual(1, _sink.Packets.Count);
        var bytes = _sink.Packets[0];

        Assert.IsTrue(Ipv6Packet.TryParse(bytes, out var ip));
        Assert.AreEqual(IpProtocol.Udp, ip.NextHeader);
        Assert.AreEqual(Server, ip.Source, "the reply must appear to come from the server the client asked");
        Assert.AreEqual(Client, ip.Destination);
        Assert.IsTrue(UdpDatagram.TryParse(ip.Payload, out var udp));
        Assert.AreEqual((ushort)53, udp.SourcePort);
        Assert.AreEqual((ushort)50000, udp.DestinationPort);
        Assert.AreEqual(
            BinaryPrimitives.ReadUInt16BigEndian(query),
            BinaryPrimitives.ReadUInt16BigEndian(udp.Payload),
            "the client's own identifier must come back");
    }

    [TestMethod]
    public void MixedFamilies_CoexistInOneFlowTable()
    {
        var v4Client = Packets.Address("192.168.255.2");
        var v4Server = Packets.Address("1.1.1.1");

        _ = _stack.Offer(Packets.Tcp(v4Client, v4Server, 40001, 80, 1, 0, TcpFlags.Syn, default, 1460));
        Syn();

        Assert.AreEqual(2, _stack.FlowCount);
        Assert.AreEqual(2, _channels.OpenRequests);
    }

    /// <summary>A minimal, well-formed DNS query: header plus one question.</summary>
    private static byte[] BuildDnsQuery()
    {
        var message = new List<byte>();
        message.AddRange(new byte[] { 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
        message.AddRange(new byte[] { 7 });
        message.AddRange(Encoding.ASCII.GetBytes("example"));
        message.AddRange(new byte[] { 3 });
        message.AddRange(Encoding.ASCII.GetBytes("com"));
        message.AddRange(new byte[] { 0, 0x00, 0x01, 0x00, 0x01 });
        return message.ToArray();
    }
}
