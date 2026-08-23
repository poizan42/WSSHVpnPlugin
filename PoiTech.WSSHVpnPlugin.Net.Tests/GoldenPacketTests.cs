using System;
using System.Buffers.Binary;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.Net.Tests;

/// <summary>
/// Byte-exact pins of the IPv4 wire output, against an independent reconstruction.
/// </summary>
/// <remarks>
/// <para>
/// The expected bytes are built here, field by field from the RFC layouts, with a definitional
/// checksum - not with the production writers, which would prove nothing. The initial sequence
/// number is read back from the actual output where one is involved, because it is derived from a
/// per-process hash seed and is arbitrary by specification; every other byte is pinned.
/// </para>
/// <para>
/// These exist to hold the v4 wire format still while the address types underneath it widen for
/// IPv6. A failure here means a v4 byte changed, which no refactoring step is allowed to do.
/// </para>
/// </remarks>
[TestClass]
public class GoldenPacketTests
{
    private static readonly IpAddr Client = Packets.Address("192.168.255.2");
    private static readonly IpAddr Server = Packets.Address("1.1.1.1");
    private const ushort ClientPort = 40000;
    private const ushort ServerPort = 80;

    [TestMethod]
    public void TcpWriters_MatchAnIndependentConstruction()
    {
        var payload = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01 };
        var actual = Packets.Tcp(
            Client, Server, ClientPort, ServerPort,
            sequenceNumber: 0x11223344, acknowledgementNumber: 0x55667788,
            TcpFlags.Ack | TcpFlags.Psh, payload, mss: 1460, windowSize: 8192);

        var expected = BuildIpv4(
            protocol: 6, Client.V4, Server.V4,
            BuildTcp(Client.V4, Server.V4, ClientPort, ServerPort,
                0x11223344, 0x55667788, flags: 0x18, window: 8192,
                options: [2, 4, 0x05, 0xB4], payload));

        CollectionAssert.AreEqual(expected, actual);
    }

    [TestMethod]
    public void UdpWriters_MatchAnIndependentConstruction()
    {
        var payload = new byte[] { 0x12, 0x34, 0x56 };
        var buffer = new byte[200];
        payload.CopyTo(buffer.AsSpan(Ipv4Packet.MinimumHeaderLength + UdpDatagram.HeaderLength));
        var udpLength = UdpDatagram.Write(
            buffer.AsSpan(Ipv4Packet.MinimumHeaderLength), Server, Client, 53, ClientPort, payload.Length);
        var total = Ipv4Packet.Write(buffer, IpProtocol.Udp, Server.V4, Client.V4, udpLength);
        var actual = buffer.AsSpan(0, total).ToArray();

        var expected = BuildIpv4(protocol: 17, Server.V4, Client.V4, BuildUdp(Server.V4, Client.V4, 53, ClientPort, payload));

        CollectionAssert.AreEqual(expected, actual);
    }

    [TestMethod]
    public void SynAck_FromTheStack_MatchesAnIndependentConstruction()
    {
        var (stack, sink) = Drive();
        _ = stack.Offer(Packets.Tcp(Client, Server, ClientPort, ServerPort, 1000, 0, TcpFlags.Syn, default, mss: 1460));
        _ = stack.RunOnce();

        var reply = sink.Last();
        Assert.AreEqual(TcpFlags.Syn | TcpFlags.Ack, reply.Flags);

        var expected = BuildIpv4(
            protocol: 6, Server.V4, Client.V4,
            BuildTcp(Server.V4, Client.V4, ServerPort, ClientPort,
                reply.Seq, acknowledgement: 1001, flags: 0x12, window: 32768,
                options: [2, 4, 0x05, 0x50], payload: []));

        CollectionAssert.AreEqual(expected, sink.Packets[^1]);
    }

    [TestMethod]
    public void Reset_FromTheStack_MatchesAnIndependentConstruction()
    {
        var (stack, sink) = Drive(failOpens: true);
        _ = stack.Offer(Packets.Tcp(Client, Server, ClientPort, ServerPort, 1000, 0, TcpFlags.Syn, default, mss: 1460));
        _ = stack.RunOnce();

        var reply = sink.Last();
        Assert.IsTrue(reply.Flags.HasFlag(TcpFlags.Rst), $"expected a reset, got {reply.Flags}");

        var expected = BuildIpv4(
            protocol: 6, Server.V4, Client.V4,
            BuildTcp(Server.V4, Client.V4, ServerPort, ClientPort,
                reply.Seq, reply.Ack, flags: (byte)reply.Flags, window: ReadWindow(sink.Packets[^1]),
                options: [], payload: []));

        CollectionAssert.AreEqual(expected, sink.Packets[^1]);
    }

    private static (StackLoop Stack, FakeSink Sink) Drive(bool failOpens = false)
    {
        var channels = new FakeChannelFactory { FailOpens = failOpens };
        var sink = new FakeSink();
        return (new StackLoop(channels, sink, new FakeClock(), mtu: 1400), sink);
    }

    private static ushort ReadWindow(byte[] packet)
        => BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(Ipv4Packet.MinimumHeaderLength + 14, 2));

    /// <summary>The RFC 1071 checksum, written as the definition: 16-bit words, end-around carry.</summary>
    private static ushort ChecksumDefinitional(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        for (var i = 0; i + 1 < data.Length; i += 2)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(i, 2));
        }

        if (data.Length % 2 != 0)
        {
            sum += (uint)(data[^1] << 8);
        }

        while (sum > 0xFFFF)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)~sum;
    }

    private static byte[] BuildIpv4(byte protocol, uint source, uint destination, byte[] payload)
    {
        var packet = new byte[20 + payload.Length];
        packet[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)packet.Length);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6, 2), 0x4000);
        packet[8] = 64;
        packet[9] = protocol;
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(12, 4), source);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(16, 4), destination);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10, 2), ChecksumDefinitional(packet.AsSpan(0, 20)));
        payload.CopyTo(packet.AsSpan(20));
        return packet;
    }

    private static byte[] BuildTcp(
        uint source,
        uint destination,
        ushort sourcePort,
        ushort destinationPort,
        uint sequence,
        uint acknowledgement,
        byte flags,
        ushort window,
        byte[] options,
        byte[] payload)
    {
        var headerLength = 20 + options.Length;
        var segment = new byte[headerLength + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(segment.AsSpan(0, 2), sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(segment.AsSpan(2, 2), destinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(segment.AsSpan(4, 4), sequence);
        BinaryPrimitives.WriteUInt32BigEndian(segment.AsSpan(8, 4), acknowledgement);
        segment[12] = (byte)((headerLength / 4) << 4);
        segment[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(segment.AsSpan(14, 2), window);
        options.CopyTo(segment.AsSpan(20));
        payload.CopyTo(segment.AsSpan(headerLength));

        BinaryPrimitives.WriteUInt16BigEndian(
            segment.AsSpan(16, 2),
            ChecksumDefinitional(WithV4PseudoHeader(source, destination, protocol: 6, segment)));
        return segment;
    }

    private static byte[] BuildUdp(uint source, uint destination, ushort sourcePort, ushort destinationPort, byte[] payload)
    {
        var datagram = new byte[8 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(datagram.AsSpan(0, 2), sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(datagram.AsSpan(2, 2), destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(datagram.AsSpan(4, 2), (ushort)datagram.Length);
        payload.CopyTo(datagram.AsSpan(8));

        var checksum = ChecksumDefinitional(WithV4PseudoHeader(source, destination, protocol: 17, datagram));
        BinaryPrimitives.WriteUInt16BigEndian(datagram.AsSpan(6, 2), checksum == 0 ? (ushort)0xFFFF : checksum);
        return datagram;
    }

    private static byte[] WithV4PseudoHeader(uint source, uint destination, byte protocol, byte[] segment)
    {
        var whole = new byte[12 + segment.Length];
        BinaryPrimitives.WriteUInt32BigEndian(whole.AsSpan(0, 4), source);
        BinaryPrimitives.WriteUInt32BigEndian(whole.AsSpan(4, 4), destination);
        whole[9] = protocol;
        BinaryPrimitives.WriteUInt16BigEndian(whole.AsSpan(10, 2), (ushort)segment.Length);
        segment.CopyTo(whole.AsSpan(12));
        return whole;
    }
}
