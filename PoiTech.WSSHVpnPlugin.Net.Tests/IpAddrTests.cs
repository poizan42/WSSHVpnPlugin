using System;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.Net.Tests;

/// <summary>
/// Pins the dual-family address value type: the v4-mapped convention, family derivation, and the
/// formatting the logs depend on.
/// </summary>
[TestClass]
public class IpAddrTests
{
    [TestMethod]
    public void FromV4_RoundTrips_AndReportsV4()
    {
        var address = IpAddr.FromV4(0xC0A8FF02);

        Assert.IsTrue(address.IsV4);
        Assert.AreEqual(0xC0A8FF02u, address.V4);
        Assert.AreEqual(Ipv4Packet.MinimumHeaderLength, address.HeaderLength);
    }

    [TestMethod]
    public void ReadV6_WriteV6_RoundTrips()
    {
        Span<byte> bytes = stackalloc byte[16];
        for (var i = 0; i < 16; i++)
        {
            bytes[i] = (byte)(i + 1);
        }

        var address = IpAddr.ReadV6(bytes);

        Span<byte> written = stackalloc byte[16];
        address.WriteV6(written);

        CollectionAssert.AreEqual(bytes.ToArray(), written.ToArray());
        Assert.IsFalse(address.IsV4);
        Assert.AreEqual(Ipv6Packet.HeaderLength, address.HeaderLength);
    }

    /// <summary>
    /// The v4-mapped form is the storage convention, so parsing the mapped text must land on the
    /// same value as wrapping the v4 address - otherwise one flow could exist twice in a table.
    /// </summary>
    [TestMethod]
    public void Parse_V4MappedText_EqualsFromV4()
    {
        Assert.AreEqual(IpAddr.FromV4(0x01020304), IpAddr.Parse("::ffff:1.2.3.4"));
        Assert.AreEqual(IpAddr.FromV4(0x01020304), IpAddr.Parse("1.2.3.4"));
    }

    [TestMethod]
    public void Parse_V6Text_RoundTripsThroughFormat()
    {
        var address = IpAddr.Parse("2001:db8::1");

        Assert.IsFalse(address.IsV4);
        Assert.AreEqual("2001:db8::1", address.Format());
    }

    /// <summary>
    /// Neighbours of the mapped prefix must not read as v4: the unspecified address, a v6 address
    /// with the prefix bits in the wrong half, and the mapped prefix with a non-zero high half.
    /// </summary>
    [TestMethod]
    public void IsV4_RejectsLookalikes()
    {
        Assert.IsFalse(IpAddr.Parse("::").IsV4);
        Assert.IsFalse(IpAddr.Parse("::1").IsV4);
        Assert.IsFalse(IpAddr.Parse("64:ff9b::1.2.3.4").IsV4, "NAT64 well-known prefix is not v4-mapped");
        Assert.IsFalse(new IpAddr(1, 0x0000_FFFF_01020304).IsV4, "a non-zero high half is not v4-mapped");
    }

    [TestMethod]
    public void Format_ProducesDottedQuadForV4()
    {
        Assert.AreEqual("192.168.255.2", IpAddr.FromV4(0xC0A8FF02).Format());
    }

    [TestMethod]
    public void FormatEndpoint_BracketsOnlyV6()
    {
        Assert.AreEqual("1.2.3.4:443", IpAddr.Parse("1.2.3.4").FormatEndpoint(443));
        Assert.AreEqual("[2001:db8::1]:443", IpAddr.Parse("2001:db8::1").FormatEndpoint(443));
    }

    [TestMethod]
    public void Equality_And_Hashing_DistinguishFamilies()
    {
        var v4 = IpAddr.FromV4(1);
        var v6 = IpAddr.Parse("::1");

        Assert.AreNotEqual(v4, v6);
        Assert.AreEqual(IpAddr.Parse("2001:db8::1"), IpAddr.Parse("2001:db8:0:0:0:0:0:1"));
    }
}
