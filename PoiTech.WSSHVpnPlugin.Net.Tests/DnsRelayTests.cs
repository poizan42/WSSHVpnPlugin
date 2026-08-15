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
    private const ushort ClientId = 0x1234;

    private static readonly uint Client = Packets.Address("192.168.255.2");
    private static readonly uint Server = Packets.Address("1.1.1.1");

    private FakeSink _sink = null!;
    private FakeClock _clock = null!;
    private DnsRelay _relay = null!;
    private FakeChannel? _channel;
    private List<(uint Address, ushort Port)> _opens = null!;
    private bool _refuseOpen;
    private bool _deferOpen;
    private Action? _completeOpen;

    [TestInitialize]
    public void Initialize()
    {
        _sink = new FakeSink();
        _clock = new FakeClock();
        _opens = new List<(uint, ushort)>();
        _refuseOpen = false;
        _deferOpen = false;
        _completeOpen = null;

        _relay = new DnsRelay(_sink, _clock, (address, port, onOpened, onFailed) =>
        {
            _opens.Add((address, port));

            if (_refuseOpen)
            {
                onFailed();
                return;
            }

            if (_deferOpen)
            {
                _completeOpen = () =>
                {
                    _channel = new FakeChannel();
                    onOpened(_channel);
                };

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

    /// <summary>
    /// The point of pipelining: a burst of names costs one channel, not one each. Opening per query
    /// is what exhausted the channel limit in the first minute of every real connection.
    /// </summary>
    [TestMethod]
    public void Further_queries_reuse_the_same_channel()
    {
        for (var i = 0; i < 20; i++)
        {
            OfferQuery(BuildQuery());
            _ = _relay.RunOnce();
        }

        Assert.AreEqual(1, _opens.Count, "one channel should serve them all");
        Assert.AreEqual(1, _relay.Channels);
        Assert.AreEqual(20, SentRequests().Count, "every query should still have been sent");
    }

    [TestMethod]
    public void Query_is_sent_with_a_length_prefix_and_our_own_identifier()
    {
        var query = BuildQuery();
        OfferQuery(query);
        _ = _relay.RunOnce();

        var sent = SentRequests();
        Assert.AreEqual(1, sent.Count);

        // Everything but the identifier is passed through untouched.
        CollectionAssert.AreEqual(query[2..], sent[0].Message[2..]);
        Assert.AreNotEqual(ClientId, sent[0].Id, "the client's identifier must not go on the wire");
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
    public void Reply_comes_back_as_a_datagram_with_the_clients_identifier()
    {
        var query = BuildQuery();
        OfferQuery(query);
        _ = _relay.RunOnce();

        DeliverReply(SentRequests()[0].Id, BuildReply(query, answers: 1));
        _ = _relay.RunOnce();

        Assert.AreEqual(1, _sink.Packets.Count);
        AssertIsUdpFromServer(_sink.Packets[0]);

        var payload = PayloadOf(_sink.Packets[0]);
        Assert.AreEqual(ClientId, BinaryPrimitives.ReadUInt16BigEndian(payload), "the client's own identifier must come back");
        Assert.AreEqual(1, _relay.Answered);
        Assert.AreEqual(0, _relay.Outstanding);
    }

    [TestMethod]
    public void Reply_is_assembled_from_several_arrivals()
    {
        var query = BuildQuery();
        OfferQuery(query);
        _ = _relay.RunOnce();

        var framed = Frame(SentRequests()[0].Id, BuildReply(query, answers: 1));

        // A length prefix split across arrivals is what breaks a reader that assumes framing
        // survives the stream.
        foreach (var b in framed)
        {
            _channel!.ReceiveFromPeer(b);
            _ = _relay.RunOnce();
        }

        Assert.AreEqual(1, _sink.Packets.Count);
        Assert.AreEqual(1, _relay.Answered);
    }

    /// <summary>
    /// Replies may come back in any order, which is the whole reason identifiers are rewritten
    /// rather than the stream being treated as a queue.
    /// </summary>
    [TestMethod]
    public void Replies_out_of_order_reach_the_right_clients()
    {
        var first = BuildQuery();
        var second = BuildQuery();

        OfferQueryFrom(60001, first);
        OfferQueryFrom(60002, second);
        _ = _relay.RunOnce();

        var sent = SentRequests();
        Assert.AreEqual(2, sent.Count);

        // Answer the second one first.
        DeliverReply(sent[1].Id, BuildReply(second, answers: 1));
        _ = _relay.RunOnce();
        DeliverReply(sent[0].Id, BuildReply(first, answers: 1));
        _ = _relay.RunOnce();

        Assert.AreEqual(2, _sink.Packets.Count);

        Assert.IsTrue(UdpDatagram.TryParse(Ipv4PayloadOf(_sink.Packets[0]), out var one));
        Assert.AreEqual((ushort)60002, one.DestinationPort, "the first answer belongs to the second asker");

        Assert.IsTrue(UdpDatagram.TryParse(Ipv4PayloadOf(_sink.Packets[1]), out var two));
        Assert.AreEqual((ushort)60001, two.DestinationPort);
    }

    [TestMethod]
    public void Reply_too_large_for_a_datagram_is_truncated_not_dropped()
    {
        var query = BuildQuery();
        OfferQuery(query);
        _ = _relay.RunOnce();

        DeliverReply(SentRequests()[0].Id, BuildReply(query, answers: 1, padding: 2000));
        _ = _relay.RunOnce();

        Assert.AreEqual(1, _sink.Packets.Count);
        Assert.AreEqual(1, _relay.Truncated);

        var payload = PayloadOf(_sink.Packets[0]);

        Assert.AreEqual(0x80, payload[2] & 0x80, "it must be marked a response");
        Assert.AreEqual(0x02, payload[2] & 0x02, "the truncated bit must be set");
        Assert.AreEqual(ClientId, BinaryPrimitives.ReadUInt16BigEndian(payload), "the identifier must match the query");
        Assert.AreEqual(0, BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(6, 2)), "no answers survive");
    }

    /// <summary>
    /// The stream has to stay in step even when an answer is unusable: a reply larger than we keep
    /// must still be consumed in full, or the next length is read from the middle of it.
    /// </summary>
    [TestMethod]
    public void An_oversize_reply_does_not_desync_the_stream()
    {
        var first = BuildQuery();
        var second = BuildQuery();

        OfferQueryFrom(60001, first);
        OfferQueryFrom(60002, second);
        _ = _relay.RunOnce();

        var sent = SentRequests();

        // A reply far larger than the buffer, immediately followed by an ordinary one.
        DeliverReply(sent[0].Id, BuildReply(first, answers: 1, padding: 40000));
        DeliverReply(sent[1].Id, BuildReply(second, answers: 1));
        _ = _relay.RunOnce();

        Assert.AreEqual(1, _relay.Truncated, "the oversize one is answered with TC");
        Assert.AreEqual(1, _relay.Answered, "and the one behind it survives intact");
        Assert.AreEqual(2, _sink.Packets.Count);
    }

    /// <summary>A reply nobody is waiting for must be consumed, not left to desync the stream.</summary>
    [TestMethod]
    public void An_unknown_identifier_is_discarded_without_desyncing()
    {
        var query = BuildQuery();
        OfferQuery(query);
        _ = _relay.RunOnce();

        var id = SentRequests()[0].Id;

        DeliverReply((ushort)(id + 999), BuildReply(query, answers: 1));
        DeliverReply(id, BuildReply(query, answers: 1));
        _ = _relay.RunOnce();

        Assert.AreEqual(1, _relay.Answered, "the real answer still lands");
        Assert.AreEqual(1, _sink.Packets.Count);
    }

    [TestMethod]
    public void Reply_within_the_advertised_edns_size_is_not_truncated()
    {
        var query = BuildQuery(ednsPayloadSize: 4096);
        OfferQuery(query);
        _ = _relay.RunOnce();

        DeliverReply(SentRequests()[0].Id, BuildReply(query, answers: 1, padding: 800));
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

        DeliverReply(SentRequests()[0].Id, BuildReply(query, answers: 1, padding: 600));
        _ = _relay.RunOnce();

        Assert.AreEqual(1, _relay.Truncated);
    }

    [TestMethod]
    public void Reply_larger_than_the_tunnel_mtu_is_truncated_even_when_edns_allows_it()
    {
        var query = BuildQuery(ednsPayloadSize: 4096);
        OfferQuery(query);
        _ = _relay.RunOnce();

        DeliverReply(SentRequests()[0].Id, BuildReply(query, answers: 1, padding: 1500));
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
        Assert.IsTrue(_relay.Dropped >= 1);
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
        Assert.AreEqual(1, _relay.Dropped);
    }

    /// <summary>
    /// An identifier freed by a timeout must not be handed straight to the next query, or a late
    /// reply is delivered as somebody else's answer.
    /// </summary>
    [TestMethod]
    public void An_identifier_is_not_reused_straight_after_a_timeout()
    {
        OfferQuery(BuildQuery());
        _ = _relay.RunOnce();
        var first = SentRequests()[0].Id;

        _clock.Advance(TimeSpan.FromSeconds(10));
        _ = _relay.RunOnce();

        OfferQuery(BuildQuery());
        _ = _relay.RunOnce();

        Assert.AreNotEqual(first, SentRequests()[1].Id, "the abandoned identifier is still reserved");
    }

    [TestMethod]
    public void Reply_that_cannot_be_queued_is_retried_rather_than_lost()
    {
        var query = BuildQuery();
        OfferQuery(query);
        _ = _relay.RunOnce();

        DeliverReply(SentRequests()[0].Id, BuildReply(query, answers: 1));

        _sink.Full = true;
        _ = _relay.RunOnce();
        Assert.AreEqual(0, _sink.Packets.Count);

        _sink.Full = false;
        _ = _relay.RunOnce();
        Assert.AreEqual(1, _sink.Packets.Count);
    }

    [TestMethod]
    public void Server_hanging_up_drops_what_was_in_flight()
    {
        OfferQuery(BuildQuery());
        _ = _relay.RunOnce();

        _channel!.IsPeerEof = true;
        _ = _relay.RunOnce();

        Assert.AreEqual(0, _sink.Packets.Count);
        Assert.AreEqual(0, _relay.Outstanding);
        Assert.IsTrue(_relay.Dropped >= 1);
    }

    [TestMethod]
    public void Queries_beyond_the_outstanding_limit_are_refused()
    {
        for (var i = 0; i < 64; i++)
        {
            OfferQuery(BuildQuery());
        }

        Assert.AreEqual(64, _relay.Outstanding);
        Assert.IsFalse(TryOfferQuery(60000, BuildQuery()));
        Assert.AreEqual(64, _relay.Outstanding);
    }

    /// <summary>Hands a query to the relay the way <see cref="StackLoop"/> would.</summary>
    private void OfferQuery(byte[] message) => OfferQueryFrom(ClientPort, message);

    private void OfferQueryFrom(ushort clientPort, byte[] message)
    {
        Assert.IsTrue(TryOfferQuery(clientPort, message));
    }

    private bool TryOfferQuery(ushort clientPort, byte[] message)
    {
        var buffer = new byte[UdpDatagram.HeaderLength + message.Length];
        message.CopyTo(buffer, UdpDatagram.HeaderLength);
        _ = UdpDatagram.Write(buffer, Client, Server, clientPort, 53, message.Length);

        Assert.IsTrue(UdpDatagram.TryParse(buffer, out var datagram));
        return _relay.Offer(Client, Server, datagram);
    }

    /// <summary>Reads back the length-framed requests the relay has written to the channel.</summary>
    private List<(ushort Id, byte[] Message)> SentRequests()
    {
        var sent = _channel!.Sent.ToArray();
        var requests = new List<(ushort, byte[])>();
        var offset = 0;

        while (offset + 2 <= sent.Length)
        {
            var length = BinaryPrimitives.ReadUInt16BigEndian(sent.AsSpan(offset, 2));
            if (offset + 2 + length > sent.Length)
            {
                break;
            }

            var message = sent[(offset + 2)..(offset + 2 + length)];
            requests.Add((BinaryPrimitives.ReadUInt16BigEndian(message), message));
            offset += 2 + length;
        }

        return requests;
    }

    private void DeliverReply(ushort id, byte[] message)
    {
        _channel!.ReceiveFromPeer(Frame(id, message));
    }

    private static byte[] Frame(ushort id, byte[] message)
    {
        var framed = new byte[2 + message.Length];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)message.Length);
        message.CopyTo(framed, 2);

        // The server answers with whatever identifier it was asked with.
        BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(2), id);
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

        // Nothing under test parses an answer record, so only its length matters here.
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
    }

    private static byte[] Ipv4PayloadOf(byte[] packet)
    {
        Assert.IsTrue(Ipv4Packet.TryParse(packet, out var ip));
        return ip.Payload.ToArray();
    }

    private static byte[] PayloadOf(byte[] packet)
    {
        Assert.IsTrue(UdpDatagram.TryParse(Ipv4PayloadOf(packet), out var udp));
        return udp.Payload.ToArray();
    }
}
