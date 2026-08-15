using System;
using System.Buffers.Binary;
using System.Net;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.Net.Tests;

[TestClass]
public class PacketParsingTests
{
    private static uint Address(string dotted)
    {
        return BinaryPrimitives.ReadUInt32BigEndian(IPAddress.Parse(dotted).GetAddressBytes());
    }

    /// <summary>
    /// Builds a TCP-over-IPv4 packet the way the stack does, so the tests exercise the writers as
    /// well as the readers.
    /// </summary>
    private static byte[] BuildTcpPacket(
        string source,
        string destination,
        ushort sourcePort,
        ushort destinationPort,
        uint sequenceNumber,
        uint acknowledgementNumber,
        TcpFlags flags,
        ReadOnlySpan<byte> payload,
        ushort? mss = null)
    {
        var buffer = new byte[1500];
        var src = Address(source);
        var dst = Address(destination);

        var tcpStart = Ipv4Packet.MinimumHeaderLength;
        var headerLength = TcpSegment.MinimumHeaderLength + (mss.HasValue ? 4 : 0);
        payload.CopyTo(buffer.AsSpan(tcpStart + headerLength));

        var tcpLength = TcpSegment.Write(
            buffer.AsSpan(tcpStart),
            src,
            dst,
            sourcePort,
            destinationPort,
            sequenceNumber,
            acknowledgementNumber,
            flags,
            windowSize: 65535,
            payload.Length,
            mss);

        var total = Ipv4Packet.Write(buffer, IpProtocol.Tcp, src, dst, tcpLength);
        return buffer.AsSpan(0, total).ToArray();
    }

    [TestMethod]
    public void Ipv4_RoundTripsThroughWriteAndParse()
    {
        var packet = BuildTcpPacket("192.168.255.2", "1.1.1.1", 1234, 80, 100, 200, TcpFlags.Ack, ReadOnlySpan<byte>.Empty);

        Assert.IsTrue(Ipv4Packet.TryParse(packet, out var ip));
        Assert.AreEqual(IpProtocol.Tcp, ip.Protocol);
        Assert.AreEqual(Address("192.168.255.2"), ip.Source);
        Assert.AreEqual(Address("1.1.1.1"), ip.Destination);
        Assert.AreEqual(20, ip.HeaderLength);
        Assert.AreEqual(packet.Length, ip.TotalLength);
        Assert.IsFalse(ip.IsFragment);
    }

    [TestMethod]
    public void Ipv4_HeaderChecksumIsCorrect()
    {
        var packet = BuildTcpPacket("10.0.0.1", "10.0.0.2", 1, 2, 0, 0, TcpFlags.Syn, ReadOnlySpan<byte>.Empty);

        // A correct header sums to zero when the checksum field is included.
        Assert.AreEqual(0, InternetChecksum.Compute(packet.AsSpan(0, 20)));
    }

    [TestMethod]
    public void Ipv4_TooShort_IsRejected()
    {
        Assert.IsFalse(Ipv4Packet.TryParse(new byte[19], out _));
    }

    [TestMethod]
    public void Ipv4_NotVersionFour_IsRejected()
    {
        var packet = new byte[40];
        packet[0] = 0x65; // version 6
        Assert.IsFalse(Ipv4Packet.TryParse(packet, out _));
    }

    /// <summary>
    /// A header that claims more than the buffer holds must be refused rather than trusted; these
    /// bytes come from another machine's stack.
    /// </summary>
    [TestMethod]
    public void Ipv4_TotalLengthBeyondTheBuffer_IsRejected()
    {
        var packet = BuildTcpPacket("10.0.0.1", "10.0.0.2", 1, 2, 0, 0, TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)(packet.Length + 1));

        Assert.IsFalse(Ipv4Packet.TryParse(packet, out _));
    }

    [TestMethod]
    public void Ipv4_HeaderLengthBeyondTheBuffer_IsRejected()
    {
        var packet = new byte[24];
        packet[0] = 0x4F; // claims a 60-byte header
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), 24);

        Assert.IsFalse(Ipv4Packet.TryParse(packet, out _));
    }

    [TestMethod]
    public void Ipv4_Fragment_IsRecognised()
    {
        var packet = BuildTcpPacket("10.0.0.1", "10.0.0.2", 1, 2, 0, 0, TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6, 2), 0x2000); // more fragments

        Assert.IsTrue(Ipv4Packet.TryParse(packet, out var ip));
        Assert.IsTrue(ip.IsFragment);
    }

    [TestMethod]
    public void Tcp_RoundTripsThroughWriteAndParse()
    {
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var packet = BuildTcpPacket("192.168.255.2", "1.1.1.1", 4321, 443, 0xDEADBEEF, 0x12345678, TcpFlags.Ack | TcpFlags.Psh, payload);

        Assert.IsTrue(Ipv4Packet.TryParse(packet, out var ip));
        Assert.IsTrue(TcpSegment.TryParse(ip.Payload, out var tcp));

        Assert.AreEqual(4321, tcp.SourcePort);
        Assert.AreEqual(443, tcp.DestinationPort);
        Assert.AreEqual(0xDEADBEEFu, tcp.SequenceNumber);
        Assert.AreEqual(0x12345678u, tcp.AcknowledgementNumber);
        Assert.AreEqual(TcpFlags.Ack | TcpFlags.Psh, tcp.Flags);
        Assert.AreEqual(65535, tcp.WindowSize);
        CollectionAssert.AreEqual(payload, tcp.Payload.ToArray());
    }

    [TestMethod]
    public void Tcp_ChecksumIsValidOverThePseudoHeader()
    {
        var payload = new byte[] { 9, 8, 7 };
        var packet = BuildTcpPacket("192.168.255.2", "1.1.1.1", 1, 2, 5, 6, TcpFlags.Ack, payload);

        Assert.IsTrue(Ipv4Packet.TryParse(packet, out var ip));
        Assert.IsTrue(TcpSegment.TryParse(ip.Payload, out var tcp));
        Assert.IsTrue(tcp.IsChecksumValid(ip.Source, ip.Destination));
    }

    [TestMethod]
    public void Tcp_CorruptedChecksum_IsDetected()
    {
        var packet = BuildTcpPacket("192.168.255.2", "1.1.1.1", 1, 2, 5, 6, TcpFlags.Ack, new byte[] { 1 });
        packet[^1] ^= 0xFF;

        Assert.IsTrue(Ipv4Packet.TryParse(packet, out var ip));
        Assert.IsTrue(TcpSegment.TryParse(ip.Payload, out var tcp));
        Assert.IsFalse(tcp.IsChecksumValid(ip.Source, ip.Destination));
    }

    /// <summary>
    /// The platform may hand us segments with no checksum at all if it treats the tunnel interface
    /// as offload-capable. Rejecting those would blackhole every flow.
    /// </summary>
    [TestMethod]
    public void Tcp_AbsentChecksum_IsAccepted()
    {
        var packet = BuildTcpPacket("192.168.255.2", "1.1.1.1", 1, 2, 5, 6, TcpFlags.Ack, new byte[] { 1 });

        Assert.IsTrue(Ipv4Packet.TryParse(packet, out var ip));
        var tcpStart = ip.HeaderLength;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(tcpStart + 16, 2), 0);

        Assert.IsTrue(Ipv4Packet.TryParse(packet, out ip));
        Assert.IsTrue(TcpSegment.TryParse(ip.Payload, out var tcp));
        Assert.IsTrue(tcp.IsChecksumValid(ip.Source, ip.Destination));
    }

    [TestMethod]
    public void Tcp_MaximumSegmentSizeOption_IsReadBack()
    {
        var packet = BuildTcpPacket("192.168.255.2", "1.1.1.1", 1, 2, 0, 0, TcpFlags.Syn, ReadOnlySpan<byte>.Empty, mss: 1360);

        Assert.IsTrue(Ipv4Packet.TryParse(packet, out var ip));
        Assert.IsTrue(TcpSegment.TryParse(ip.Payload, out var tcp));
        Assert.AreEqual(24, tcp.HeaderLength);
        Assert.IsTrue(tcp.TryGetMaximumSegmentSize(out var mss));
        Assert.AreEqual(1360, mss);
    }

    [TestMethod]
    public void Tcp_NoOptions_ReportsNoMaximumSegmentSize()
    {
        var packet = BuildTcpPacket("192.168.255.2", "1.1.1.1", 1, 2, 0, 0, TcpFlags.Syn, ReadOnlySpan<byte>.Empty);

        Assert.IsTrue(Ipv4Packet.TryParse(packet, out var ip));
        Assert.IsTrue(TcpSegment.TryParse(ip.Payload, out var tcp));
        Assert.IsFalse(tcp.TryGetMaximumSegmentSize(out _));
    }

    /// <summary>
    /// Windows' SYN carries window scale and SACK-permitted alongside the MSS, so the option walker
    /// has to step over options it does not implement.
    /// </summary>
    [TestMethod]
    public void Tcp_MaximumSegmentSizeAmongOtherOptions_IsFound()
    {
        var buffer = new byte[60];

        // Options: NOP, window scale (3,3,7), MSS (2,4,1460), SACK-permitted (4,2), end.
        var options = new byte[] { 1, 3, 3, 7, 2, 4, 0x05, 0xB4, 4, 2, 0, 0 };
        options.CopyTo(buffer.AsSpan(TcpSegment.MinimumHeaderLength));

        buffer[12] = (byte)(((TcpSegment.MinimumHeaderLength + options.Length) / 4) << 4);
        buffer[13] = (byte)TcpFlags.Syn;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(0, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2, 2), 2);

        Assert.IsTrue(TcpSegment.TryParse(buffer.AsSpan(0, TcpSegment.MinimumHeaderLength + options.Length), out var tcp));
        Assert.IsTrue(tcp.TryGetMaximumSegmentSize(out var mss));
        Assert.AreEqual(1460, mss);
    }

    [TestMethod]
    public void Tcp_OptionLengthRunningOffTheEnd_IsRejectedRatherThanRead()
    {
        var buffer = new byte[28];
        buffer[12] = (byte)((28 / 4) << 4);
        buffer[13] = (byte)TcpFlags.Syn;

        // An MSS option claiming to be longer than the options area.
        buffer[TcpSegment.MinimumHeaderLength] = 2;
        buffer[TcpSegment.MinimumHeaderLength + 1] = 40;

        Assert.IsTrue(TcpSegment.TryParse(buffer, out var tcp));
        Assert.IsFalse(tcp.TryGetMaximumSegmentSize(out _));
    }

    [TestMethod]
    public void Tcp_TooShort_IsRejected()
    {
        Assert.IsFalse(TcpSegment.TryParse(new byte[19], out _));
    }

    [TestMethod]
    public void Tcp_DataOffsetBeyondTheBuffer_IsRejected()
    {
        var buffer = new byte[24];
        buffer[12] = 0xF0; // claims a 60-byte header
        Assert.IsFalse(TcpSegment.TryParse(buffer, out _));
    }

    [TestMethod]
    public void Checksum_OddLengthPadsOnTheRight()
    {
        // 0x1234 followed by a lone 0x56 must sum as 0x1234 + 0x5600.
        var expected = InternetChecksum.Finish(0x1234u + 0x5600u);
        Assert.AreEqual(expected, InternetChecksum.Compute(new byte[] { 0x12, 0x34, 0x56 }));
    }
}
