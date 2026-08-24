using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// Chooses the tunnel interface's own client addresses, avoiding what the machine already reaches.
/// </summary>
/// <remarks>
/// <para>
/// An assigned client address becomes a host route on the tunnel interface, and a host route beats
/// every other prefix length — so an address that collides with something reachable makes that thing
/// unreachable for as long as the tunnel is up, silently. The routing table is where such a claim is
/// published, which makes reading it before assigning a coordination protocol rather than a
/// heuristic: whoever claims first is legible to whoever comes next.
/// </para>
/// <para>
/// Pure, and deliberately so: the caller supplies the claims it read and the addresses it wants
/// avoided, and the answer is a function of those. Everything platform-shaped — enumerating routes,
/// deciding when to run — stays outside, which is what lets this be exercised against a brute-force
/// oracle in a fast test instead of a deploy.
/// </para>
/// <para>
/// The two families need different mechanisms, and the asymmetry is the point. No IPv4 range is safe
/// by construction, so v4 is chosen by <em>observation</em>: subtract what is claimed from a pool and
/// take what is left. IPv6 needs no observation to be safe, only entropy, because a ULA global ID
/// that is not the lazy all-zero value collides with nothing — so v6 is <em>derived</em>, and then
/// checked with the same machinery for the one case entropy cannot help with, another interface of
/// ours on the same machine.
/// </para>
/// </remarks>
internal static class ClientAddressAllocator
{
    /// <summary>
    /// The IPv4 pools, tried in order.
    /// </summary>
    /// <remarks>
    /// RFC 2544 benchmarking space first, then the three RFC 5737 documentation ranges. None is a
    /// legitimate internet destination, so an address taken from one shadows nothing real — which is
    /// the most that can be said for any IPv4 range, since none is safe by construction. Proxy
    /// tooling parks fake addresses in <c>198.18.0.0/15</c> and documentation prefixes get
    /// copy-pasted into real configuration, which is what the claim check is for. RFC 6598 CGNAT
    /// space is deliberately absent: it is in production use by ISPs, and it is where Tailscale
    /// assigns from.
    /// </remarks>
    private static readonly IpPrefix[] V4Pools =
    [
        IpPrefix.Parse("198.18.0.0/15"),
        IpPrefix.Parse("192.0.2.0/24"),
        IpPrefix.Parse("198.51.100.0/24"),
        IpPrefix.Parse("203.0.113.0/24"),
    ];

    /// <summary>
    /// How many IPv6 subnet identifiers to try before giving up.
    /// </summary>
    /// <remarks>
    /// A derived prefix is only unavailable if something else on this machine claims the whole
    /// <c>/64</c>, which takes a deliberate act. The subnet field exists to be varied, so a handful
    /// of attempts is generous; the bound is here so that a pathological claim cannot spin.
    /// </remarks>
    private const int SubnetAttempts = 4;

    /// <summary>
    /// Picks an IPv4 address for the tunnel.
    /// </summary>
    /// <param name="claims">Prefixes the machine already reaches, from the routing table.</param>
    /// <param name="avoid">Addresses that must not be chosen whatever the routes say.</param>
    /// <param name="exhausted">
    /// Set when every pool was claimed and the answer is the unchecked natural choice, which the
    /// caller should report: it is the one case where the returned address may collide.
    /// </param>
    public static IpAddr AllocateV4(
        IReadOnlyList<IpPrefix> claims,
        IReadOnlyList<IpAddr> avoid,
        out bool exhausted)
    {
        return Allocate(V4Pools, claims, avoid, out exhausted);
    }

    /// <summary>
    /// Derives an IPv6 address for the tunnel, and steps it if this machine already claims it.
    /// </summary>
    /// <param name="host">The profile's server host, which identifies the prefix.</param>
    /// <param name="claims">Prefixes the machine already reaches, from the routing table.</param>
    /// <param name="avoid">Addresses that must not be chosen whatever the routes say.</param>
    /// <param name="exhausted">Set when every derived prefix was claimed. See <see cref="AllocateV4"/>.</param>
    public static IpAddr AllocateV6(
        string host,
        IReadOnlyList<IpPrefix> claims,
        IReadOnlyList<IpAddr> avoid,
        out bool exhausted)
    {
        ArgumentNullException.ThrowIfNull(host);

        var pools = new IpPrefix[SubnetAttempts];
        for (var subnet = 0; subnet < SubnetAttempts; subnet++)
        {
            pools[subnet] = new IpPrefix(DeriveUniqueLocalPrefix(host, (ushort)subnet), 64);
        }

        return Allocate(pools, claims, avoid, out exhausted);
    }

    /// <summary>
    /// Derives the unique local prefix this host's tunnel uses, as its network address.
    /// </summary>
    /// <param name="host">The profile's server host.</param>
    /// <param name="subnet">The subnet identifier, varied only when a prefix is already claimed.</param>
    /// <remarks>
    /// <para>
    /// RFC 4193 requires the 40-bit global identifier to be chosen so that prefixes are unlikely to
    /// coincide, and forbids well-known values — which is exactly what <c>fd00::/8</c> with an
    /// all-zero identifier is, and why it is the value most likely to be shared with some other
    /// product that also picked it lazily. A digest of the server host satisfies the requirement in
    /// the only scope that can matter here: the address never leaves this machine, since SSH carries
    /// the destination as text and the server connects from its own address, so two machines sharing
    /// a profile share a prefix without ever meeting.
    /// </para>
    /// <para>
    /// The digest must be a real hash rather than <see cref="string.GetHashCode()"/>, which is
    /// randomised per process — the prefix has to be the same on every connect, and a per-process
    /// seed would silently make it change.
    /// </para>
    /// </remarks>
    public static IpAddr DeriveUniqueLocalPrefix(string host, ushort subnet)
    {
        ArgumentNullException.ThrowIfNull(host);

        // Host names are case-insensitive, so a difference in case must not produce a different
        // "stable" prefix.
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(host.Trim().ToLowerInvariant()));

        ulong globalId = 0;
        for (var i = 0; i < 5; i++)
        {
            globalId = (globalId << 8) | digest[i];
        }

        if (globalId == 0)
        {
            // Vanishingly unlikely, and the one value that must never be produced: it is the lazy
            // fd00::/8 prefix this exists to avoid.
            globalId = 1;
        }

        // fd | 40-bit global id | 16-bit subnet id, then a zero interface id.
        return new IpAddr((0xFDUL << 56) | (globalId << 16) | subnet, 0);
    }

    /// <summary>
    /// Takes the lowest unclaimed address of the earliest pool that has one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A claim counts only if the pool <em>contains</em> it. That single test is what makes this
    /// correct rather than a threshold picked by hand: a route broader than the whole pool is a
    /// coarse routing decision that happens to cover it, not a statement about any address in it.
    /// The half-default idiom is the case that matters — <c>0.0.0.0/1</c> and <c>128.0.0.0/1</c>,
    /// which this very plug-in publishes for its own tunnel, cover every pool, and honouring them
    /// would make the allocator fall back to a fixed address whenever any full-tunnel VPN is up,
    /// including a second profile of this one. The same holds for <c>8000::/1</c> against a derived
    /// prefix, where stepping could never escape it.
    /// </para>
    /// <para>
    /// <see cref="IpPrefix.Subtract"/> does the deciding, so the answer is exact rather than sampled:
    /// trying a few candidate offsets fails whenever a claim covers the low end of a pool, which is
    /// precisely what proxy tooling installs, and falls through a pool that is almost entirely free.
    /// Subtraction also sorts its cover by network address, so the first survivor's network is the
    /// lowest free address — and it is the one routine here with a brute-force oracle behind it.
    /// </para>
    /// </remarks>
    internal static IpAddr Allocate(
        IReadOnlyList<IpPrefix> pools,
        IReadOnlyList<IpPrefix> claims,
        IReadOnlyList<IpAddr> avoid,
        out bool exhausted)
    {
        ArgumentNullException.ThrowIfNull(pools);
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(avoid);

        var holes = new List<IpPrefix>();

        foreach (var pool in pools)
        {
            holes.Clear();
            AddReserved(pool, holes);

            foreach (var address in avoid)
            {
                var claim = HostPrefix(address);
                if (pool.Contains(claim))
                {
                    holes.Add(claim);
                }
            }

            foreach (var claim in claims)
            {
                if (pool.Contains(claim))
                {
                    holes.Add(claim);
                }
            }

            var free = IpPrefix.Subtract([pool], holes);

            if (free.Count > 0)
            {
                exhausted = false;
                return free[0].Network;
            }
        }

        // Nothing was free anywhere. The natural choice is still better than refusing to connect: a
        // tunnel that starts with a colliding address loses one destination, and one that does not
        // start loses everything. The caller reports it.
        exhausted = true;
        return NaturalChoice(pools[0]);
    }

    /// <summary>
    /// Reserves the addresses of a pool that should not be handed out.
    /// </summary>
    /// <remarks>
    /// The pool's own network address goes in both families: for IPv6 it is the subnet-router anycast
    /// address, and for IPv4 it is the one a naive validator somewhere is most likely to reject. The
    /// second reservation differs — IPv4 keeps its last address out for the same defensive reason,
    /// while IPv6 reserves one more so that the first address handed out is <c>::2</c>, which is what
    /// this tunnel has always used. Whether the platform would accept either is untested and costs a
    /// deploy to find out on a channel that can only be started once, so the caution is cheap
    /// insurance rather than a correctness claim.
    /// </remarks>
    private static void AddReserved(IpPrefix pool, List<IpPrefix> holes)
    {
        holes.Add(HostPrefix(pool.Network));
        holes.Add(HostPrefix(pool.IsV4 ? pool.Last : Next(pool.Network)));
    }

    /// <summary>Gets the address a pool would yield with nothing claimed.</summary>
    private static IpAddr NaturalChoice(IpPrefix pool)
    {
        var first = Next(pool.Network);
        return pool.IsV4 ? first : Next(first);
    }

    private static IpPrefix HostPrefix(IpAddr address)
    {
        return new IpPrefix(address, address.IsV4 ? 32 : 128);
    }

    /// <summary>Gets the address after this one.</summary>
    private static IpAddr Next(IpAddr address)
    {
        if (address.IsV4)
        {
            return IpAddr.FromV4(address.V4 + 1);
        }

        var low = address.Low + 1;
        return new IpAddr(low == 0 ? address.High + 1 : address.High, low);
    }
}
