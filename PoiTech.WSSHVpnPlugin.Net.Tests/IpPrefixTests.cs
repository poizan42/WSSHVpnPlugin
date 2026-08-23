using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.Net.Tests;

/// <summary>
/// Prefix subtraction is how the tunnel's routes get computed, so it is checked against a
/// brute-force address-set oracle rather than against hand-written expectations alone - once per
/// family, since the arithmetic is width-parameterised and a bug could hide in either width.
/// </summary>
/// <remarks>
/// The property that matters operationally is coverage, not shape: every address that was included
/// and not excluded must still be routed, and no excluded address may be. A wrong answer either
/// black-holes traffic or silently keeps sending an excluded range into a tunnel that cannot carry
/// it, and both look like a network fault rather than a bug in here.
/// </remarks>
[TestClass]
public class IpPrefixTests
{
    /// <summary>
    /// Enumerates the v4 addresses a prefix list covers, as an oracle for small cases.
    /// </summary>
    private static HashSet<uint> Cover(IEnumerable<IpPrefix> prefixes)
    {
        var addresses = new HashSet<uint>();
        foreach (var prefix in prefixes)
        {
            for (var address = prefix.Network.V4; ; address++)
            {
                _ = addresses.Add(address);
                if (address == prefix.Last.V4)
                {
                    break;
                }
            }
        }

        return addresses;
    }

    /// <summary>
    /// Enumerates the v6 addresses a prefix list covers, as low 64-bit values inside one test /120.
    /// </summary>
    private static HashSet<ulong> CoverV6(IEnumerable<IpPrefix> prefixes)
    {
        var addresses = new HashSet<ulong>();
        foreach (var prefix in prefixes)
        {
            for (var address = prefix.Network.Low; ; address++)
            {
                _ = addresses.Add(address);
                if (address == prefix.Last.Low)
                {
                    break;
                }
            }
        }

        return addresses;
    }

    [TestMethod]
    public void ParseAcceptsCidrAndBareAddress()
    {
        Assert.AreEqual(new IpPrefix(IpAddr.FromV4(0x0A000000), 8), IpPrefix.Parse("10.0.0.0/8"));
        Assert.AreEqual(new IpPrefix(IpAddr.FromV4(0xC0000201), 32), IpPrefix.Parse("192.0.2.1"));
        Assert.AreEqual(new IpPrefix(IpAddr.FromV4(0), 0), IpPrefix.Parse("0.0.0.0/0"));
    }

    [TestMethod]
    public void ParseAcceptsV6CidrAndBareAddress()
    {
        Assert.AreEqual(new IpPrefix(IpAddr.Parse("2001:db8::"), 32), IpPrefix.Parse("2001:db8::/32"));
        Assert.AreEqual(new IpPrefix(IpAddr.Parse("2001:db8::1"), 128), IpPrefix.Parse("2001:db8::1"));
        Assert.AreEqual(new IpPrefix(IpAddr.Parse("::"), 0), IpPrefix.Parse("::/0"));
        Assert.AreEqual(new IpPrefix(IpAddr.Parse("::"), 1), IpPrefix.Parse("::/1"));
        Assert.AreEqual(new IpPrefix(IpAddr.Parse("8000::"), 1), IpPrefix.Parse("8000::/1"));
    }

    [TestMethod]
    public void ParseMasksHostBitsOff()
    {
        // A host address with a shorter length names the same route as its network does;
        // configuration written either way must reach the platform as the network.
        Assert.AreEqual(IpPrefix.Parse("198.51.100.0/24"), IpPrefix.Parse("198.51.100.207/24"));
        Assert.AreEqual(IpPrefix.Parse("2001:db8::/64"), IpPrefix.Parse("2001:db8::dead:beef/64"));
    }

    [TestMethod]
    [DataRow("nonsense")]
    [DataRow("198.51.100.0/33")]
    [DataRow("198.51.100.0/x")]
    [DataRow("198.51.100/24")]
    [DataRow("198.51.100.256/24")]
    [DataRow("198.51.100.0/-1")]
    [DataRow("2001:db8::/129")]
    [DataRow("2001:zz8::/32")]
    [DataRow("::ffff:1.2.3.4/96")]
    public void ParseRejectsMalformed(string value)
    {
        _ = Assert.ThrowsException<FormatException>(() => IpPrefix.Parse(value));
    }

    [TestMethod]
    public void ToStringRoundTrips()
    {
        foreach (var text in new[]
        {
            "0.0.0.0/0", "128.0.0.0/1", "10.0.0.0/8", "198.51.100.42/32",
            "::/0", "::/1", "8000::/1", "2001:db8::/32", "2001:db8::1/128",
        })
        {
            Assert.AreEqual(text, IpPrefix.Parse(text).ToString());
        }
    }

    [TestMethod]
    public void SubtractingNothingKeepsTheInclusionSetUnchanged()
    {
        var included = new[] { IpPrefix.Parse("0.0.0.0/1"), IpPrefix.Parse("128.0.0.0/1") };

        var result = IpPrefix.Subtract(included, Array.Empty<IpPrefix>());

        CollectionAssert.AreEqual(included, result.ToArray());
    }

    [TestMethod]
    public void SubtractingADisjointPrefixKeepsTheInclusionSetUnchanged()
    {
        var included = new[] { IpPrefix.Parse("10.0.0.0/8") };

        var result = IpPrefix.Subtract(included, new[] { IpPrefix.Parse("192.168.0.0/16") });

        CollectionAssert.AreEqual(included, result.ToArray());
    }

    [TestMethod]
    public void SubtractingTheWholeInclusionSetLeavesNothing()
    {
        // The caller must treat this as a configuration error: a tunnel with no routes carries
        // nothing, which is a far worse outcome than a range that failed to be excluded.
        var result = IpPrefix.Subtract(
            new[] { IpPrefix.Parse("0.0.0.0/1"), IpPrefix.Parse("128.0.0.0/1") },
            new[] { IpPrefix.Parse("0.0.0.0/0") });

        Assert.AreEqual(0, result.Count);
    }

    /// <summary>
    /// The two families are disjoint spaces: a hole of one family passes through an inclusion list
    /// of the other without touching it. This is what makes <c>::/0</c> in the exclusions mean
    /// "no IPv6 routes" without disturbing the v4 set.
    /// </summary>
    [TestMethod]
    public void AHoleOfOneFamilyDoesNotTouchTheOther()
    {
        var included = new[]
        {
            IpPrefix.Parse("0.0.0.0/1"), IpPrefix.Parse("128.0.0.0/1"),
            IpPrefix.Parse("::/1"), IpPrefix.Parse("8000::/1"),
        };

        var result = IpPrefix.Subtract(included, new[] { IpPrefix.Parse("::/0") });

        CollectionAssert.AreEqual(
            new[] { IpPrefix.Parse("0.0.0.0/1"), IpPrefix.Parse("128.0.0.0/1") },
            result.ToArray());

        Assert.IsFalse(IpPrefix.Parse("::/0").Contains(IpPrefix.Parse("0.0.0.0/0")));
        Assert.IsFalse(IpPrefix.Parse("0.0.0.0/0").Contains(IpPrefix.Parse("::/0")));
        Assert.IsFalse(IpPrefix.Parse("::/0").Overlaps(IpPrefix.Parse("10.0.0.0/8")));
    }

    [TestMethod]
    public void SubtractingASubnetFromTheHalfDefaultsCoversEverythingElseExactly()
    {
        var included = new[] { IpPrefix.Parse("0.0.0.0/1"), IpPrefix.Parse("128.0.0.0/1") };
        var excluded = IpPrefix.Parse("198.51.100.0/24");

        var result = IpPrefix.Subtract(included, new[] { excluded });

        // No survivor may touch the hole...
        foreach (var prefix in result)
        {
            Assert.IsFalse(prefix.Overlaps(excluded), $"{prefix} overlaps the excluded {excluded}");
        }

        // ...and together they must still account for every address outside it. 2^32 minus a /24,
        // counted rather than enumerated.
        var covered = result.Aggregate(0UL, (total, prefix) => total + (ulong)prefix.Last.V4 - prefix.Network.V4 + 1);
        Assert.AreEqual((1UL << 32) - 256, covered);
    }

    [TestMethod]
    public void SubtractionIsMinimalForASingleHole()
    {
        // A /24 carved out of the two half-defaults needs one prefix per bit from /1 down to /24,
        // which is 24 - 1 + 1 = 24 from the containing half, plus the other half untouched.
        var result = IpPrefix.Subtract(
            new[] { IpPrefix.Parse("0.0.0.0/1"), IpPrefix.Parse("128.0.0.0/1") },
            new[] { IpPrefix.Parse("198.51.100.0/24") });

        Assert.AreEqual(24, result.Count);
    }

    /// <summary>
    /// The same minimality at v6 widths: a /64 carved out of the half-defaults needs one prefix per
    /// bit from /1 down to /64, plus the untouched half - and the count is the thing that reaches
    /// the platform as a route list, so it is worth pinning exactly.
    /// </summary>
    [TestMethod]
    public void SubtractionIsMinimalForASingleV6Hole()
    {
        var result = IpPrefix.Subtract(
            new[] { IpPrefix.Parse("::/1"), IpPrefix.Parse("8000::/1") },
            new[] { IpPrefix.Parse("2001:db8:1:2::/64") });

        Assert.AreEqual(64, result.Count);

        foreach (var prefix in result)
        {
            Assert.IsFalse(prefix.Overlaps(IpPrefix.Parse("2001:db8:1:2::/64")), $"{prefix} overlaps the hole");
        }
    }

    [TestMethod]
    public void SubtractionNeverReturnsOverlappingPrefixes()
    {
        var result = IpPrefix.Subtract(
            new[] { IpPrefix.Parse("0.0.0.0/1"), IpPrefix.Parse("128.0.0.0/1") },
            new[]
            {
                IpPrefix.Parse("10.0.0.0/8"),
                IpPrefix.Parse("172.16.0.0/12"),
                IpPrefix.Parse("192.168.0.0/16"),
                IpPrefix.Parse("198.51.100.42/32"),
            });

        for (var i = 0; i < result.Count; i++)
        {
            for (var j = i + 1; j < result.Count; j++)
            {
                Assert.IsFalse(
                    result[i].Overlaps(result[j]),
                    $"{result[i]} overlaps {result[j]}");
            }
        }
    }

    [TestMethod]
    public void OverlappingAndNestedHolesAreHandledAsAUnion()
    {
        // A /16 inside a /8 that is also excluded must not confuse the recursion.
        var wide = IpPrefix.Subtract(
            new[] { IpPrefix.Parse("10.0.0.0/8") },
            new[] { IpPrefix.Parse("10.0.0.0/8"), IpPrefix.Parse("10.1.0.0/16") });

        Assert.AreEqual(0, wide.Count);
    }

    /// <summary>
    /// The oracle test: over a small address space, subtraction must produce exactly the set
    /// difference, for every combination of holes.
    /// </summary>
    /// <remarks>
    /// Enumerating 2^32 addresses is not an option, so the space is scaled down by working inside a
    /// single <c>/24</c> and excluding <c>/28</c>..<c>/32</c> pieces of it. The recursion has no
    /// special cases per prefix length, so a bug that survives this would have to be length-specific.
    /// </remarks>
    [TestMethod]
    public void SubtractionMatchesSetDifferenceOverASmallSpace()
    {
        var space = IpPrefix.Parse("198.51.100.0/24");
        var candidates = new[]
        {
            IpPrefix.Parse("198.51.100.0/28"),
            IpPrefix.Parse("198.51.100.16/28"),
            IpPrefix.Parse("198.51.100.64/26"),
            IpPrefix.Parse("198.51.100.200/32"),
            IpPrefix.Parse("198.51.100.128/25"),
        };

        var full = Cover(new[] { space });

        // Every subset of the candidate holes.
        for (var mask = 0; mask < 1 << candidates.Length; mask++)
        {
            var holes = new List<IpPrefix>();
            for (var bit = 0; bit < candidates.Length; bit++)
            {
                if ((mask & (1 << bit)) != 0)
                {
                    holes.Add(candidates[bit]);
                }
            }

            var expected = new HashSet<uint>(full);
            expected.ExceptWith(Cover(holes));

            var actual = Cover(IpPrefix.Subtract(new[] { space }, holes));

            Assert.IsTrue(
                expected.SetEquals(actual),
                $"mask {mask}: expected {expected.Count} addresses, got {actual.Count}");
        }
    }

    /// <summary>
    /// The same oracle at v6 widths, inside a documentation-prefix /120: the arithmetic is
    /// width-parameterised, so the mirror run catches anything 128-bit-specific - a shift past 64,
    /// a mask built in the wrong half.
    /// </summary>
    [TestMethod]
    public void SubtractionMatchesSetDifferenceOverASmallV6Space()
    {
        var space = IpPrefix.Parse("2001:db8::ff00/120");
        var candidates = new[]
        {
            IpPrefix.Parse("2001:db8::ff00/124"),
            IpPrefix.Parse("2001:db8::ff10/124"),
            IpPrefix.Parse("2001:db8::ff40/122"),
            IpPrefix.Parse("2001:db8::ffc8/128"),
            IpPrefix.Parse("2001:db8::ff80/121"),
        };

        var full = CoverV6(new[] { space });

        for (var mask = 0; mask < 1 << candidates.Length; mask++)
        {
            var holes = new List<IpPrefix>();
            for (var bit = 0; bit < candidates.Length; bit++)
            {
                if ((mask & (1 << bit)) != 0)
                {
                    holes.Add(candidates[bit]);
                }
            }

            var expected = new HashSet<ulong>(full);
            expected.ExceptWith(CoverV6(holes));

            var actual = CoverV6(IpPrefix.Subtract(new[] { space }, holes));

            Assert.IsTrue(
                expected.SetEquals(actual),
                $"mask {mask}: expected {expected.Count} addresses, got {actual.Count}");
        }
    }

    [TestMethod]
    public void ContainsAndOverlapsAgreeOnNestingAndDisjointness()
    {
        var eight = IpPrefix.Parse("10.0.0.0/8");
        var sixteen = IpPrefix.Parse("10.1.0.0/16");
        var elsewhere = IpPrefix.Parse("192.168.0.0/16");

        Assert.IsTrue(eight.Contains(sixteen));
        Assert.IsFalse(sixteen.Contains(eight));
        Assert.IsTrue(eight.Overlaps(sixteen));
        Assert.IsTrue(sixteen.Overlaps(eight));
        Assert.IsFalse(eight.Overlaps(elsewhere));
        Assert.IsTrue(eight.Contains(eight));
    }

    [TestMethod]
    public void ADefaultRouteContainsEverythingAndAHostRouteOnlyItself()
    {
        var all = IpPrefix.Parse("0.0.0.0/0");
        var host = IpPrefix.Parse("198.51.100.42/32");

        Assert.IsTrue(all.Contains(host));
        Assert.IsTrue(all.Contains(all));
        Assert.IsFalse(host.Contains(all));
        Assert.AreEqual(host.Network, host.Last);
        Assert.AreEqual(uint.MaxValue, all.Last.V4);

        var all6 = IpPrefix.Parse("::/0");
        var host6 = IpPrefix.Parse("2001:db8::1/128");

        Assert.IsTrue(all6.Contains(host6));
        Assert.IsFalse(host6.Contains(all6));
        Assert.AreEqual(host6.Network, host6.Last);
        Assert.AreEqual(new IpAddr(ulong.MaxValue, ulong.MaxValue), all6.Last);
    }
}
