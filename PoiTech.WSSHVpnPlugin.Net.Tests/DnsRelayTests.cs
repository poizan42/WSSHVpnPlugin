using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.Net.Tests;

/// <summary>
/// Drives <see cref="DnsRelay"/> with synthetic queries and a fake channel.
/// </summary>
[TestClass]
public sealed class DnsRelayTests
{
    private const ushort ClientPort = 50000;

    private static readonly uint Client = Packets.Address("192.168.255.2");
    private static readonly uint Server = Packets.Address("1.1.1.1");

    private FakeSink _sink = null!;
    private FakeClock _clock = null!;
    private DnsRelay _relay = null!;
    private FakeChannel? _channel;
    private List<(uint Address, ushort Port)> _opens = null!;
    private bool _refuseOpen;

    [TestInitialize]
    public void Initialize()
    {
        _sink = new FakeSink();
        _clock = new FakeClock();
        _opens = new List<(uint, ushort)>();
        _refuseOpen = false;

        _relay = new DnsRelay(_sink, _clock, (address, port, onOpened, onFailed) =>
        {
            _opens.Add((address, port));

            if (_refuseOpen)
            {
                onFailed();
                return;
            }

            _channel = new FakeChannel();
            onOpened(_channel);
        });
    }

    [TestMethod]
    public void Offer_opens_a_channel_to_the_server_on_port_53()
    {
        OfferQuery(BuildQuery());

        CollectionAssert.AreEqual(new[] { (Server, (ushort)53) }, _opens);
    }

    [TestMethod]
    public void Query_is_sent_with_a_two_byte_length_prefix()
    {
        var query = BuildQuery();
        OfferQuery(query);
        _ = _relay.RunOnce();

        var sent = _channel!.Sent.ToArray();

        Assert.AreEqual(query.Length, BinaryPrimitives.ReadUInt16BigEndian(sent));
        CollectionAssert.AreEqual(query, sent[2..]);
    }

    [TestMethod]
    public void Query_resumes_after_a_partial_send()
    {
        var query = BuildQuery();
        OfferQuery(query);

        // One byte per pass, so the send has to survive being interrupted anywhere in the frame -
        // including between the two bytes of the length prefix.
        _channel!.SendLimit = 1;

        for (var i = 0; i < query.Length + 2; i++)
        {
            _ = _relay.RunOnce();
        }

        Assert.AreEqual(query.Length + 2, _channel.Sent.Count);
    }

    [TestMethod]
    public void Reply_comes_back_as_a_datagram_from_the_server()
    {
        var query = BuildQuery();
        OfferQuery(query);
        _ = _relay.RunOnce();

        var reply = BuildReply(query, answers: 1);
        DeliverFramed(reply);
        _ = _relay.RunOnce();

        Assert.AreEqual(1, _sink.Packets.Count);
        AssertIsUdpFromServer(_sink.Packets[0]);
        CollectionAssert.AreEqual(reply, PayloadOf(_sink.Packets[0]));
        Assert.AreEqual(1, _relay.Answered);
        Assert.AreEqual(0, _relay.Outstanding);
    }

    [TestMethod]
    public void Reply_is_assembled_from_several_arrivals()
    {
        var query = BuildQuery();
        OfferQuery(query);
        _ = _relay.RunOnce();

        var reply = BuildReply(query, answers: 1);
        var framed = Frame(reply);

        // A length prefix split across arrivals is what breaks a reader that assumes framing
        // survives the stream.
        foreach (var b in framed)
        {
            _channel!.ReceiveFromPeer(b);
            _ = _relay.RunOnce();
        }

        Assert.AreEqual(1, _sink.Packets.Count);
        CollectionAssert.AreEqual(reply, PayloadOf(_sink.Packets[0]));
    }

    [TestMethod]
    public void Reply_too_large_for_a_datagram_is_truncated_not_dropped()
    {
        var query = BuildQuery();
        OfferQuery(query);
        _ = _relay.RunOnce();

        DeliverFramed(BuildReply(query, answers: 1, padding: 2000));
        _ = _relay.RunOnce();

        Assert.AreEqual(1, _sink.Packets.Count);
        Assert.AreEqual(1, _relay.Truncated);

        var payload = PayloadOf(_sink.Packets[0]);

        Assert.AreEqual(0x80, payload[2] & 0x80, "it must be marked a response");
        Assert.AreEqual(0x02, payload[2] & 0x02, "the truncated bit must be set");
        Assert.AreEqual(0x1234, BinaryPrimitives.ReadUInt16BigEndian(payload), "the identifier must match the query");
        Assert.AreEqual(1, BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(4, 2)), "the question is echoed");
        Assert.AreEqual(0, BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(6, 2)), "no answers survive");
        Assert.AreEqual(0, BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(8, 2)), "no authorities survive");
        Assert.AreEqual(0, BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(10, 2)), "no additionals survive");
    }

    [TestMethod]
    public void Reply_within_the_advertised_edns_size_is_not_truncated()
    {
        var query = BuildQuery(ednsPayloadSize: 4096);
        OfferQuery(query);
        _ = _relay.RunOnce();

        // Beyond the classic 512 limit, and still deliverable in one datagram.
        DeliverFramed(BuildReply(query, answers: 1, padding: 800));
        _ = _relay.RunOnce();

        Assert.AreEqual(0, _relay.Truncated);
        Assert.AreEqual(1, _relay.Answered);
    }

    [TestMethod]
    public void Reply_beyond_512_is_truncated_when_the_query_carries_no_edns()
    {
        var query = BuildQuery();
        OfferQuery(query);
        _ = _relay.RunOnce();

        DeliverFramed(BuildReply(query, answers: 1, padding: 600));
        _ = _relay.RunOnce();

        Assert.AreEqual(1, _relay.Truncated);
    }

    [TestMethod]
    public void Reply_larger_than_the_tunnel_mtu_is_truncated_even_when_edns_allows_it()
    {
        // The client says it will take 4096, but nothing here fragments, so the MTU is the ceiling.
        var query = BuildQuery(ednsPayloadSize: 4096);
        OfferQuery(query);
        _ = _relay.RunOnce();

        DeliverFramed(BuildReply(query, answers: 1, padding: 1500));
        _ = _relay.RunOnce();

        Assert.AreEqual(1, _relay.Truncated);
    }

    [TestMethod]
    public void Query_whose_channel_fails_is_dropped_silently()
    {
        _refuseOpen = true;
        OfferQuery(BuildQuery());
        _ = _relay.RunOnce();

        Assert.AreEqual(0, _sink.Packets.Count);
        Assert.AreEqual(0, _relay.Outstanding);
        Assert.AreEqual(1, _relay.Dropped);
    }

    [TestMethod]
    public void Query_that_is_never_answered_is_reaped()
    {
        OfferQuery(BuildQuery());
        _ = _relay.RunOnce();

        Assert.AreEqual(1, _relay.Outstanding);

        _clock.Advance(TimeSpan.FromSeconds(10));
        _ = _relay.RunOnce();

        Assert.AreEqual(0, _relay.Outstanding);
        Assert.IsTrue(_channel!.Disposed, "the channel must not leak");
    }

    [TestMethod]
    public void Reply_that_cannot_be_queued_is_retried_rather_than_lost()
    {
        var query = BuildQuery();
        OfferQuery(query);
        _ = _relay.RunOnce();

        var reply = BuildReply(query, answers: 1);
        DeliverFramed(reply);

        _sink.Full = true;
        _ = _relay.RunOnce();
        Assert.AreEqual(0, _sink.Packets.Count);
        Assert.AreEqual(1, _relay.Outstanding);

        _sink.Full = false;
        _ = _relay.RunOnce();
        Assert.AreEqual(1, _sink.Packets.Count);
        CollectionAssert.AreEqual(reply, PayloadOf(_sink.Packets[0]));
    }

    [TestMethod]
    public void Server_hanging_up_mid_reply_drops_the_query()
    {
        OfferQuery(BuildQuery());
        _ = _relay.RunOnce();

        // A length prefix promising 256 bytes, and one byte of them.
        _channel!.ReceiveFromPeer(0x01, 0x00, 0x00);
        _channel.IsPeerEof = true;
        _ = _relay.RunOnce();

        Assert.AreEqual(0, _sink.Packets.Count);
        Assert.AreEqual(0, _relay.Outstanding);
        Assert.AreEqual(1, _relay.Dropped);
    }

    [TestMethod]
    public void Queries_beyond_the_outstanding_limit_are_refused()
    {
        // A resolver reads the refusal as loss and asks again, which is what UDP already does.
        for (var i = 0; i < 16; i++)
        {
            OfferQuery(BuildQuery());
        }

        Assert.AreEqual(16, _relay.Outstanding);
        Assert.IsFalse(TryOfferQuery(BuildQuery()));
        Assert.AreEqual(16, _relay.Outstanding);
    }

    /// <summary>Hands a query to the relay the way <see cref="StackLoop"/> would.</summary>
    private void OfferQuery(byte[] message)
    {
        Assert.IsTrue(TryOfferQuery(message));
    }

    private bool TryOfferQuery(byte[] message)
    {
        var buffer = new byte[UdpDatagram.HeaderLength + message.Length];
        message.CopyTo(buffer, UdpDatagram.HeaderLength);
        _ = UdpDatagram.Write(buffer, Client, Server, ClientPort, 53, message.Length);

        Assert.IsTrue(UdpDatagram.TryParse(buffer, out var datagram));
        return _relay.Offer(Client, Server, datagram);
    }

    private void DeliverFramed(byte[] message)
    {
        _channel!.ReceiveFromPeer(Frame(message));
    }

    private static byte[] Frame(byte[] message)
    {
        var framed = new byte[2 + message.Length];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)message.Length);
        message.CopyTo(framed, 2);
        return framed;
    }

    /// <summary>Builds a query for <c>example.com</c>, optionally carrying an EDNS0 OPT record.</summary>
    private static byte[] BuildQuery(int ednsPayloadSize = 0)
    {
        var message = new List<byte>
        {
            0x12, 0x34,                                  // identifier
            0x01, 0x00,                                  // recursion desired
            0x00, 0x01,                                  // one question
            0x00, 0x00,                                  // no answers
            0x00, 0x00,                                  // no authorities
        };

        message.AddRange(ednsPayloadSize > 0 ? new byte[] { 0x00, 0x01 } : new byte[] { 0x00, 0x00 });

        message.Add(7);
        message.AddRange(Encoding.ASCII.GetBytes("example"));
        message.Add(3);
        message.AddRange(Encoding.ASCII.GetBytes("com"));
        message.Add(0);
        message.AddRange(new byte[] { 0x00, 0x01 });     // type A
        message.AddRange(new byte[] { 0x00, 0x01 });     // class IN

        if (ednsPayloadSize > 0)
        {
            message.Add(0);                              // the root name
            message.AddRange(new byte[] { 0x00, 0x29 }); // type OPT

            var size = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(size, (ushort)ednsPayloadSize);
            message.AddRange(size);                      // class: the payload size the client accepts

            message.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 });  // extended rcode and flags
            message.AddRange(new byte[] { 0x00, 0x00 });              // no option data
        }

        return message.ToArray();
    }

    /// <summary>Builds a reply to a query, padded to whatever size the test needs.</summary>
    private static byte[] BuildReply(byte[] query, int answers, int padding = 0)
    {
        var message = new List<byte>(query);

        message[2] = 0x81;                               // a response, recursion desired
        message[3] = 0x80;                               // recursion available
        BinaryPrimitives.WriteUInt16BigEndian(CollectionsMarshal.AsSpan(message)[6..8], (ushort)answers);

        // Nothing under test parses an answer record, so only its length matters here: what the tests
        // turn on is where the reply as a whole falls against the size limits.
        for (var i = 0; i < answers; i++)
        {
            message.AddRange(new byte[] { 0xC0, 0x0C });                    // name: a pointer to the question
            message.AddRange(new byte[] { 0x00, 0x01, 0x00, 0x01 });        // type A, class IN
            message.AddRange(new byte[] { 0x00, 0x00, 0x01, 0x2C });        // ttl
            message.AddRange(new byte[] { 0x00, 0x04 });                    // four bytes of data
            message.AddRange(new byte[] { 93, 184, 215, 14 });
        }

        message.AddRange(new byte[padding]);
        return message.ToArray();
    }

    private static void AssertIsUdpFromServer(byte[] packet)
    {
        Assert.IsTrue(Ipv4Packet.TryParse(packet, out var ip));
        Assert.AreEqual(IpProtocol.Udp, ip.Protocol);
        Assert.AreEqual(Server, ip.Source, "the reply must appear to come from the server the client asked");
        Assert.AreEqual(Client, ip.Destination);

        Assert.IsTrue(UdpDatagram.TryParse(ip.Payload, out var udp));
        Assert.AreEqual((ushort)53, udp.SourcePort);
        Assert.AreEqual(ClientPort, udp.DestinationPort);
    }

    private static byte[] PayloadOf(byte[] packet)
    {
        Assert.IsTrue(Ipv4Packet.TryParse(packet, out var ip));
        Assert.IsTrue(UdpDatagram.TryParse(ip.Payload, out var udp));
        return udp.Payload.ToArray();
    }
}
