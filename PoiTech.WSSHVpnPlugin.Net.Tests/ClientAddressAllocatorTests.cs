using System;
using System.Collections.Generic;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.Net.Tests;

/// <summary>
/// The allocator decides which address the tunnel claims, so it is checked against a brute-force
/// oracle rather than against hand-written expectations alone.
/// </summary>
/// <remarks>
/// A wrong answer here is silent: the tunnel comes up and one destination stops working. Examples
/// alone would pass while an off-by-one in the reserved addresses, or a claim filter that honours the
/// wrong routes, shipped — so the oracle transcribes the specification literally (the lowest
/// non-reserved address of the earliest pool that no contained claim covers) and the two agree over
/// every combination of a randomised claim set.
/// </remarks>
[TestClass]
public class ClientAddressAllocatorTests
{
    private static readonly IpPrefix[] NoClaims = Array.Empty<IpPrefix>();
    private static readonly IpAddr[] NothingAvoided = Array.Empty<IpAddr>();

    /// <summary>
    /// Small stand-ins for the real pools, so the oracle can enumerate every address in them.
    /// </summary>
    private static readonly IpPrefix[] SyntheticPools =
    [
        IpPrefix.Parse("198.18.0.0/28"),
        IpPrefix.Parse("198.18.0.64/28"),
    ];

    // ---- The oracle -------------------------------------------------------------------------

    /// <summary>
    /// The specification, written as a linear scan: the lowest address of the earliest pool that is
    /// neither reserved, nor avoided, nor inside a claim the pool contains.
    /// </summary>
    private static IpAddr? OracleFirstFree(
        IReadOnlyList<IpPrefix> pools,
        IReadOnlyList<IpPrefix> claims,
        IReadOnlyList<IpAddr> avoid)
    {
        foreach (var pool in pools)
        {
            for (var value = pool.Network.V4; ; value++)
            {
                var candidate = IpAddr.FromV4(value);

                if (candidate != pool.Network &&
                    candidate != pool.Last &&
                    !IsAvoided(candidate, avoid) &&
                    !IsClaimed(pool, claims, candidate))
                {
                    return candidate;
                }

                if (value == pool.Last.V4)
                {
                    break;
                }
            }
        }

        return null;
    }

    private static bool IsAvoided(IpAddr candidate, IReadOnlyList<IpAddr> avoid)
    {
        foreach (var address in avoid)
        {
            if (address == candidate)
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsClaimed(IpPrefix pool, IReadOnlyList<IpPrefix> claims, IpAddr candidate)
    {
        var host = new IpPrefix(candidate, 32);

        foreach (var claim in claims)
        {
            // Only a claim the pool contains counts - a route broader than the pool is a routing
            // decision that happens to cover it, not a statement about this address.
            if (pool.Contains(claim) && claim.Contains(host))
            {
                return true;
            }
        }

        return false;
    }

    private static IpPrefix RandomClaim(Random random)
    {
        return random.Next(0, 10) switch
        {
            // The broad ones that must be ignored, the half-default idiom among them.
            0 => IpPrefix.Parse("0.0.0.0/0"),
            1 => IpPrefix.Parse("0.0.0.0/1"),
            2 => IpPrefix.Parse("128.0.0.0/1"),
            3 => IpPrefix.Parse("198.0.0.0/8"),
            4 => IpPrefix.Parse("2001:db8::/32"),
            5 => IpPrefix.Parse("10.0.0.0/8"),

            // And the ones that land in or across the synthetic pools.
            _ => new IpPrefix(
                IpAddr.FromV4(0xC6120000u | (uint)random.Next(0, 256)),
                random.Next(26, 33)),
        };
    }

    [TestMethod]
    public void AllocationMatchesTheOracleOverRandomClaimSets()
    {
        var random = new Random(20260824);

        for (var trial = 0; trial < 400; trial++)
        {
            var claims = new List<IpPrefix>();
            for (var i = random.Next(0, 9); i > 0; i--)
            {
                claims.Add(RandomClaim(random));
            }

            var avoid = new List<IpAddr>();
            for (var i = random.Next(0, 3); i > 0; i--)
            {
                avoid.Add(IpAddr.FromV4(0xC6120000u | (uint)random.Next(0, 128)));
            }

            var actual = ClientAddressAllocator.Allocate(SyntheticPools, claims, avoid, out var exhausted);
            var expected = OracleFirstFree(SyntheticPools, claims, avoid);

            if (expected is null)
            {
                Assert.IsTrue(exhausted, $"trial {trial}: nothing was free, so it must report exhaustion");
                Assert.AreEqual(
                    IpAddr.FromV4(SyntheticPools[0].Network.V4 + 1),
                    actual,
                    $"trial {trial}: exhaustion falls back to the first pool's natural choice");
            }
            else
            {
                Assert.IsFalse(exhausted, $"trial {trial}: {expected.Value.Format()} was free");
                Assert.AreEqual(expected.Value, actual, $"trial {trial}");
            }
        }
    }

    // ---- IPv4 against the real pools --------------------------------------------------------

    [TestMethod]
    public void WithNothingClaimed_TakesTheFirstPoolsFirstUsableAddress()
    {
        var address = ClientAddressAllocator.AllocateV4(NoClaims, NothingAvoided, out var exhausted);

        Assert.AreEqual("198.18.0.1", address.Format(), "the network address itself is reserved");
        Assert.IsFalse(exhausted);
    }

    [TestMethod]
    public void AClaimedAddress_IsSteppedOver()
    {
        var claims = new[] { IpPrefix.Parse("198.18.0.1/32") };

        var address = ClientAddressAllocator.AllocateV4(claims, NothingAvoided, out var exhausted);

        Assert.AreEqual("198.18.0.2", address.Format());
        Assert.IsFalse(exhausted);
    }

    /// <summary>
    /// The regression that matters most: this plug-in publishes the half-default pair for its own
    /// tunnel, so honouring routes broader than a pool would make the allocator inert whenever any
    /// full-tunnel VPN is up - including a second profile of this one.
    /// </summary>
    [TestMethod]
    public void TheHalfDefaultPair_DoesNotClaimAnything()
    {
        var claims = new[]
        {
            IpPrefix.Parse("0.0.0.0/0"),
            IpPrefix.Parse("0.0.0.0/1"),
            IpPrefix.Parse("128.0.0.0/1"),
            IpPrefix.Parse("196.0.0.0/6"),
        };

        var address = ClientAddressAllocator.AllocateV4(claims, NothingAvoided, out var exhausted);

        Assert.AreEqual("198.18.0.1", address.Format());
        Assert.IsFalse(exhausted);
    }

    /// <summary>
    /// Another profile of ours, connected first: its inclusion routes are ignored, but the address it
    /// actually took is honoured, so the two do not collide.
    /// </summary>
    [TestMethod]
    public void AnotherTunnelOfOurs_IsSteppedOverByItsHostRouteAlone()
    {
        var claims = new[]
        {
            IpPrefix.Parse("0.0.0.0/1"),
            IpPrefix.Parse("128.0.0.0/1"),
            IpPrefix.Parse("198.18.0.1/32"),
        };

        var address = ClientAddressAllocator.AllocateV4(claims, NothingAvoided, out _);

        Assert.AreEqual("198.18.0.2", address.Format());
    }

    [TestMethod]
    public void AFullyClaimedPool_FallsThroughToTheNext()
    {
        var claims = new[] { IpPrefix.Parse("198.18.0.0/15") };

        var address = ClientAddressAllocator.AllocateV4(claims, NothingAvoided, out var exhausted);

        Assert.AreEqual("192.0.2.1", address.Format());
        Assert.IsFalse(exhausted);
    }

    /// <summary>
    /// Proxy tooling really does route part of the benchmarking range, which is the case the pool
    /// order exists to survive.
    /// </summary>
    [TestMethod]
    public void APartlyClaimedPool_IsStillUsedWhereItIsFree()
    {
        var claims = new[] { IpPrefix.Parse("198.18.0.0/16") };

        var address = ClientAddressAllocator.AllocateV4(claims, NothingAvoided, out _);

        Assert.AreEqual("198.19.0.0", address.Format(), "the free half of the pool starts here");
    }

    [TestMethod]
    public void EveryPoolClaimed_ReportsExhaustionAndUsesTheNaturalChoice()
    {
        var claims = new[]
        {
            IpPrefix.Parse("198.18.0.0/15"),
            IpPrefix.Parse("192.0.2.0/24"),
            IpPrefix.Parse("198.51.100.0/24"),
            IpPrefix.Parse("203.0.113.0/24"),
        };

        var address = ClientAddressAllocator.AllocateV4(claims, NothingAvoided, out var exhausted);

        Assert.IsTrue(exhausted);
        Assert.AreEqual("198.18.0.1", address.Format());
    }

    /// <summary>
    /// A DNS server is reached through the tunnel, so taking its address would break every lookup -
    /// and proxy tooling parks resolvers inside the first pool, so this is not hypothetical.
    /// </summary>
    [TestMethod]
    public void AnAvoidedAddress_IsNotAllocated()
    {
        var avoid = new[] { IpAddr.Parse("198.18.0.1"), IpAddr.Parse("198.18.0.2") };

        var address = ClientAddressAllocator.AllocateV4(NoClaims, avoid, out _);

        Assert.AreEqual("198.18.0.3", address.Format());
    }

    [TestMethod]
    public void AvoidedAddressesOutsideEveryPool_CostNothing()
    {
        var avoid = new[] { IpAddr.Parse("1.1.1.1"), IpAddr.Parse("8.8.8.8") };

        var address = ClientAddressAllocator.AllocateV4(NoClaims, avoid, out _);

        Assert.AreEqual("198.18.0.1", address.Format());
    }

    // ---- IPv6 -------------------------------------------------------------------------------

    /// <summary>
    /// Pinned as a literal, not as a self-comparison. The prefix has to be the same across releases,
    /// and the byte order of the 40-bit truncation is exactly what a refactor flips silently - which
    /// a "same host twice gives the same answer" test cannot catch.
    /// </summary>
    [TestMethod]
    [DataRow("example.com", "fda3:79a6:f6ee::2")]
    [DataRow("ssh.example.net", "fd25:e810:9fa9::2")]
    public void TheDerivedAddress_IsPinnedForAKnownHost(string host, string expected)
    {
        var address = ClientAddressAllocator.AllocateV6(host, NoClaims, NothingAvoided, out var exhausted);

        Assert.AreEqual(expected, address.Format());
        Assert.IsFalse(exhausted);
    }

    [TestMethod]
    public void TheDerivedPrefix_IsAUniqueLocalOneWithANonZeroGlobalId()
    {
        var prefix = ClientAddressAllocator.DeriveUniqueLocalPrefix("example.com", 0);

        Assert.AreEqual(0xFDUL, prefix.High >> 56, "unique local addresses start fd");

        var globalId = (prefix.High >> 16) & 0xFF_FFFF_FFFFUL;
        Assert.AreNotEqual(0UL, globalId, "an all-zero global id is the lazy value this exists to avoid");
    }

    [TestMethod]
    public void TheDerivedPrefix_IgnoresHostCaseAndSurroundingSpace()
    {
        Assert.AreEqual(
            ClientAddressAllocator.DeriveUniqueLocalPrefix("ssh.example.net", 0),
            ClientAddressAllocator.DeriveUniqueLocalPrefix("  SSH.Example.NET  ", 0));
    }

    [TestMethod]
    public void DifferentHosts_DeriveDifferentPrefixes()
    {
        Assert.AreNotEqual(
            ClientAddressAllocator.DeriveUniqueLocalPrefix("example.com", 0),
            ClientAddressAllocator.DeriveUniqueLocalPrefix("example.net", 0));
    }

    /// <summary>
    /// The v6 twin of the half-default regression. Stepping an interface identifier could never
    /// escape <c>8000::/1</c>, so honouring it would not merely be wrong - it would not terminate.
    /// </summary>
    [TestMethod]
    public void TheV6HalfDefaultPair_DoesNotClaimAnything()
    {
        var claims = new[] { IpPrefix.Parse("::/1"), IpPrefix.Parse("8000::/1"), IpPrefix.Parse("fd00::/8") };

        var address = ClientAddressAllocator.AllocateV6("example.com", claims, NothingAvoided, out var exhausted);

        Assert.AreEqual("fda3:79a6:f6ee::2", address.Format());
        Assert.IsFalse(exhausted);
    }

    /// <summary>
    /// Two profiles naming the same server derive the same prefix, so the second has to step off the
    /// address the first published.
    /// </summary>
    [TestMethod]
    public void AClaimedV6Address_IsSteppedOver()
    {
        var claims = new[] { IpPrefix.Parse("fda3:79a6:f6ee::2/128") };

        var address = ClientAddressAllocator.AllocateV6("example.com", claims, NothingAvoided, out _);

        Assert.AreEqual("fda3:79a6:f6ee::3", address.Format());
    }

    [TestMethod]
    public void AFullyClaimedPrefix_StepsToTheNextSubnet()
    {
        var claims = new[] { IpPrefix.Parse("fda3:79a6:f6ee::/64") };

        var address = ClientAddressAllocator.AllocateV6("example.com", claims, NothingAvoided, out var exhausted);

        Assert.AreEqual("fda3:79a6:f6ee:1::2", address.Format());
        Assert.IsFalse(exhausted);
    }

    [TestMethod]
    public void EverySubnetClaimed_ReportsExhaustionAndTerminates()
    {
        var claims = new[]
        {
            IpPrefix.Parse("fda3:79a6:f6ee:0::/64"),
            IpPrefix.Parse("fda3:79a6:f6ee:1::/64"),
            IpPrefix.Parse("fda3:79a6:f6ee:2::/64"),
            IpPrefix.Parse("fda3:79a6:f6ee:3::/64"),
        };

        var address = ClientAddressAllocator.AllocateV6("example.com", claims, NothingAvoided, out var exhausted);

        Assert.IsTrue(exhausted);
        Assert.AreEqual("fda3:79a6:f6ee::2", address.Format());
    }

    /// <summary>
    /// A claim broader than the derived prefix is ignored, even when it is a plausible site prefix
    /// rather than a carry-everything idiom.
    /// </summary>
    /// <remarks>
    /// This is the rule's accepted false negative, pinned so that it stays a decision. Allocation
    /// happens out of a <c>/64</c>, so only claims at least that specific bear on it; something
    /// routing the whole derived <c>/48</c> would have to have drawn the same 40 bits we did, which
    /// is either a 2^-40 coincidence or deliberate.
    /// </remarks>
    [TestMethod]
    public void AClaimBroaderThanTheDerivedPrefix_IsIgnored()
    {
        var claims = new[] { IpPrefix.Parse("fda3:79a6:f6ee::/48") };

        var address = ClientAddressAllocator.AllocateV6("example.com", claims, NothingAvoided, out var exhausted);

        Assert.AreEqual("fda3:79a6:f6ee::2", address.Format());
        Assert.IsFalse(exhausted);
    }

    // ---- Contract ---------------------------------------------------------------------------

    [TestMethod]
    public void AllocationIsDeterministic()
    {
        var claims = new[] { IpPrefix.Parse("198.18.0.0/24"), IpPrefix.Parse("0.0.0.0/1") };

        var first = ClientAddressAllocator.AllocateV4(claims, NothingAvoided, out _);
        var second = ClientAddressAllocator.AllocateV4(claims, NothingAvoided, out _);

        Assert.AreEqual(first, second);
        Assert.AreEqual(
            ClientAddressAllocator.AllocateV6("example.com", claims, NothingAvoided, out _),
            ClientAddressAllocator.AllocateV6("example.com", claims, NothingAvoided, out _));
    }
}
