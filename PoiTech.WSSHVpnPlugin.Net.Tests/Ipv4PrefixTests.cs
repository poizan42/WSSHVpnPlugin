using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.Net.Tests;

/// <summary>
/// Prefix subtraction is how the tunnel's routes get computed, so it is checked against a
/// brute-force address-set oracle rather than against hand-written expectations alone.
/// </summary>
/// <remarks>
/// The property that matters operationally is coverage, not shape: every address that was included
/// and not excluded must still be routed, and no excluded address may be. A wrong answer either
/// black-holes traffic or silently keeps sending an excluded range into a tunnel that cannot carry
/// it, and both look like a network fault rather than a bug in here.
/// </remarks>
[TestClass]
public class Ipv4PrefixTests
{
    /// <summary>
    /// Enumerates the addresses a prefix list covers, as an oracle for small cases.
    /// </summary>
    private static HashSet<uint> Cover(IEnumerable<Ipv4Prefix> prefixes)
    {
        var addresses = new HashSet<uint>();
        foreach (var prefix in prefixes)
        {
            for (var address = prefix.Network; ; address++)
            {
                _ = addresses.Add(address);
                if (address == prefix.Last)
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
        Assert.AreEqual(new Ipv4Prefix(0x0A000000, 8), Ipv4Prefix.Parse("10.0.0.0/8"));
        Assert.AreEqual(new Ipv4Prefix(0xC0000201, 32), Ipv4Prefix.Parse("192.0.2.1"));
        Assert.AreEqual(new Ipv4Prefix(0, 0), Ipv4Prefix.Parse("0.0.0.0/0"));
    }

    [TestMethod]
    public void ParseMasksHostBitsOff()
    {
        // A host address with a /24 names the same route as its network does; configuration written
        // either way must reach the platform as the network.
        Assert.AreEqual(Ipv4Prefix.Parse("198.51.100.0/24"), Ipv4Prefix.Parse("198.51.100.207/24"));
    }

    [TestMethod]
    [DataRow("nonsense")]
    [DataRow("198.51.100.0/33")]
    [DataRow("198.51.100.0/x")]
    [DataRow("198.51.100/24")]
    [DataRow("198.51.100.256/24")]
    [DataRow("198.51.100.0/-1")]
    public void ParseRejectsMalformed(string value)
    {
        _ = Assert.ThrowsException<FormatException>(() => Ipv4Prefix.Parse(value));
    }

    [TestMethod]
    public void ToStringRoundTrips()
    {
        foreach (var text in new[] { "0.0.0.0/0", "128.0.0.0/1", "10.0.0.0/8", "198.51.100.42/32" })
        {
            Assert.AreEqual(text, Ipv4Prefix.Parse(text).ToString());
        }
    }

    [TestMethod]
    public void SubtractingNothingKeepsTheInclusionSetUnchanged()
    {
        var included = new[] { Ipv4Prefix.Parse("0.0.0.0/1"), Ipv4Prefix.Parse("128.0.0.0/1") };

        var result = Ipv4Prefix.Subtract(included, Array.Empty<Ipv4Prefix>());

        CollectionAssert.AreEqual(included, result.ToArray());
    }

    [TestMethod]
    public void SubtractingADisjointPrefixKeepsTheInclusionSetUnchanged()
    {
        var included = new[] { Ipv4Prefix.Parse("10.0.0.0/8") };

        var result = Ipv4Prefix.Subtract(included, new[] { Ipv4Prefix.Parse("192.168.0.0/16") });

        CollectionAssert.AreEqual(included, result.ToArray());
    }

    [TestMethod]
    public void SubtractingTheWholeInclusionSetLeavesNothing()
    {
        // The caller must treat this as a configuration error: a tunnel with no routes carries
        // nothing, which is a far worse outcome than a range that failed to be excluded.
        var result = Ipv4Prefix.Subtract(
            new[] { Ipv4Prefix.Parse("0.0.0.0/1"), Ipv4Prefix.Parse("128.0.0.0/1") },
            new[] { Ipv4Prefix.Parse("0.0.0.0/0") });

        Assert.AreEqual(0, result.Count);
    }

    [TestMethod]
    public void SubtractingASubnetFromTheHalfDefaultsCoversEverythingElseExactly()
    {
        var included = new[] { Ipv4Prefix.Parse("0.0.0.0/1"), Ipv4Prefix.Parse("128.0.0.0/1") };
        var excluded = Ipv4Prefix.Parse("198.51.100.0/24");

        var result = Ipv4Prefix.Subtract(included, new[] { excluded });

        // No survivor may touch the hole...
        foreach (var prefix in result)
        {
            Assert.IsFalse(prefix.Overlaps(excluded), $"{prefix} overlaps the excluded {excluded}");
        }

        // ...and together they must still account for every address outside it. 2^32 minus a /24,
        // counted rather than enumerated.
        var covered = result.Aggregate(0UL, (total, prefix) => total + (ulong)prefix.Last - prefix.Network + 1);
        Assert.AreEqual((1UL << 32) - 256, covered);
    }

    [TestMethod]
    public void SubtractionIsMinimalForASingleHole()
    {
        // A /24 carved out of the two half-defaults needs one prefix per bit from /1 down to /24,
        // which is 24 - 1 + 1 = 24 from the containing half, plus the other half untouched.
        var result = Ipv4Prefix.Subtract(
            new[] { Ipv4Prefix.Parse("0.0.0.0/1"), Ipv4Prefix.Parse("128.0.0.0/1") },
            new[] { Ipv4Prefix.Parse("198.51.100.0/24") });

        Assert.AreEqual(24, result.Count);
    }

    [TestMethod]
    public void SubtractionNeverReturnsOverlappingPrefixes()
    {
        var result = Ipv4Prefix.Subtract(
            new[] { Ipv4Prefix.Parse("0.0.0.0/1"), Ipv4Prefix.Parse("128.0.0.0/1") },
            new[]
            {
                Ipv4Prefix.Parse("10.0.0.0/8"),
                Ipv4Prefix.Parse("172.16.0.0/12"),
                Ipv4Prefix.Parse("192.168.0.0/16"),
                Ipv4Prefix.Parse("198.51.100.42/32"),
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
        var wide = Ipv4Prefix.Subtract(
            new[] { Ipv4Prefix.Parse("10.0.0.0/8") },
            new[] { Ipv4Prefix.Parse("10.0.0.0/8"), Ipv4Prefix.Parse("10.1.0.0/16") });

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
        var space = Ipv4Prefix.Parse("198.51.100.0/24");
        var candidates = new[]
        {
            Ipv4Prefix.Parse("198.51.100.0/28"),
            Ipv4Prefix.Parse("198.51.100.16/28"),
            Ipv4Prefix.Parse("198.51.100.64/26"),
            Ipv4Prefix.Parse("198.51.100.200/32"),
            Ipv4Prefix.Parse("198.51.100.128/25"),
        };

        var full = Cover(new[] { space });

        // Every subset of the candidate holes.
        for (var mask = 0; mask < 1 << candidates.Length; mask++)
        {
            var holes = new List<Ipv4Prefix>();
            for (var bit = 0; bit < candidates.Length; bit++)
            {
                if ((mask & (1 << bit)) != 0)
                {
                    holes.Add(candidates[bit]);
                }
            }

            var expected = new HashSet<uint>(full);
            expected.ExceptWith(Cover(holes));

            var actual = Cover(Ipv4Prefix.Subtract(new[] { space }, holes));

            Assert.IsTrue(
                expected.SetEquals(actual),
                $"mask {mask}: expected {expected.Count} addresses, got {actual.Count}");
        }
    }

    [TestMethod]
    public void ContainsAndOverlapsAgreeOnNestingAndDisjointness()
    {
        var eight = Ipv4Prefix.Parse("10.0.0.0/8");
        var sixteen = Ipv4Prefix.Parse("10.1.0.0/16");
        var elsewhere = Ipv4Prefix.Parse("192.168.0.0/16");

        Assert.IsTrue(eight.Contains(sixteen));
        Assert.IsFalse(sixteen.Contains(eight));
        Assert.IsTrue(eight.Overlaps(sixteen));
        Assert.IsTrue(sixteen.Overlaps(eight));
        Assert.IsFalse(eight.Overlaps(elsewhere));
        Assert.IsTrue(eight.Contains(eight));
    }

    [TestMethod]
    public void ADefaultRouteContainsEverythingAndASlashThirtyTwoOnlyItself()
    {
        var all = Ipv4Prefix.Parse("0.0.0.0/0");
        var host = Ipv4Prefix.Parse("198.51.100.42/32");

        Assert.IsTrue(all.Contains(host));
        Assert.IsTrue(all.Contains(all));
        Assert.IsFalse(host.Contains(all));
        Assert.AreEqual(host.Network, host.Last);
        Assert.AreEqual(uint.MaxValue, all.Last);
    }
}
