using System;
using System.Buffers.Binary;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.Net.Tests;

/// <summary>
/// Pins the IPv6 header view: what parses, what is rejected, and what <see cref="Ipv6Packet.Write"/>
/// puts on the wire.
/// </summary>
[TestClass]
public class Ipv6PacketTests
{
    private static readonly IpAddr Source = IpAddr.Parse("2001:db8::2");
    private static readonly IpAddr Destination = IpAddr.Parse("2001:db8::1");

    private static byte[] Packet(int payloadLength, int extraRoom = 0)
    {
        var buffer = new byte[Ipv6Packet.HeaderLength + payloadLength + extraRoom];
        _ = Ipv6Packet.Write(buffer, IpProtocol.Tcp, Source, Destination, payloadLength);
        return buffer;
    }

    [TestMethod]
    public void Write_RoundTripsThroughTryParse()
    {
        var buffer = Packet(payloadLength: 32);
        buffer[Ipv6Packet.HeaderLength] = 0xAB;

        Assert.IsTrue(Ipv6Packet.TryParse(buffer, out var packet));
        Assert.AreEqual(IpProtocol.Tcp, packet.NextHeader);
        Assert.AreEqual(Source, packet.Source);
        Assert.AreEqual(Destination, packet.Destination);
        Assert.AreEqual(32, packet.PayloadLength);
        Assert.AreEqual(Ipv6Packet.HeaderLength + 32, packet.TotalLength);
        Assert.AreEqual(0xAB, packet.Payload[0]);
    }

    [TestMethod]
    public void Write_SetsVersionAndHopLimit()
    {
        var buffer = Packet(payloadLength: 0);

        Assert.AreEqual(0x60, buffer[0]);
        Assert.AreEqual(64, buffer[7]);
    }

    [TestMethod]
    public void TryParse_RejectsAShortBuffer()
    {
        Assert.IsFalse(Ipv6Packet.TryParse(new byte[Ipv6Packet.HeaderLength - 1], out _));
    }

    [TestMethod]
    public void TryParse_RejectsTheWrongVersion()
    {
        var buffer = Packet(payloadLength: 0);
        buffer[0] = 0x45;

        Assert.IsFalse(Ipv6Packet.TryParse(buffer, out _));
    }

    /// <summary>
    /// A header claiming more payload than the buffer holds is the cheapest way to read off the end
    /// of it, so the claim is checked before anything reads through the view.
    /// </summary>
    [TestMethod]
    public void TryParse_RejectsAPayloadLengthBeyondTheBuffer()
    {
        var buffer = Packet(payloadLength: 8);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4, 2), 9);

        Assert.IsFalse(Ipv6Packet.TryParse(buffer, out _));
    }

    /// <summary>
    /// The platform's buffers are larger than the packets in them, so the view must clip to the
    /// declared length rather than hand out the whole buffer.
    /// </summary>
    [TestMethod]
    public void Payload_IsClippedToTheDeclaredLength()
    {
        var buffer = Packet(payloadLength: 8, extraRoom: 100);

        Assert.IsTrue(Ipv6Packet.TryParse(buffer, out var packet));
        Assert.AreEqual(8, packet.Payload.Length);
        Assert.AreEqual(Ipv6Packet.HeaderLength + 8, packet.Bytes.Length);
    }
}
