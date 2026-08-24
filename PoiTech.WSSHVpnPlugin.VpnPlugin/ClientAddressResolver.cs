using System;
using System.Collections.Generic;

using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Settles which addresses the tunnel interface will claim, and says so in the log.
/// </summary>
/// <remarks>
/// <para>
/// Joins the two halves: <see cref="RouteTable"/> reports what this machine already reaches, and
/// <see cref="ClientAddressAllocator"/> turns that into a choice. Everything family-specific lives in
/// the allocator; what is here is the profile's say in the matter, and the reporting.
/// </para>
/// <para>
/// The reporting is not incidental. A colliding client address does not break the tunnel — it makes
/// one destination quietly unreachable — so the failure is cheap to suffer and expensive to
/// understand, and nobody would think to suspect the tunnel's own address. A line naming the address,
/// where it came from, and what else reaches it is what turns that into something greppable.
/// </para>
/// </remarks>
internal static class ClientAddressResolver
{
    /// <summary>
    /// Chooses both client addresses, honouring anything the profile pins.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// A configured address is not an address, or belongs to the other family.
    /// </exception>
    public static (IpAddr V4, IpAddr V6) Resolve(SshVpnConfiguration configuration)
    {
        // A failed read is no information, not an empty world: the allocator then picks blind from
        // its first pool, which RouteTable has already reported as unreadable.
        var claims = RouteTable.TryRead() ?? Array.Empty<IpPrefix>();
        var avoid = AddressesToAvoid(configuration);

        var v4 = Resolve(configuration.ClientIPv4, "ClientIPv4", wantV4: true, configuration.Host, claims, avoid);
        var v6 = Resolve(configuration.ClientIPv6, "ClientIPv6", wantV4: false, configuration.Host, claims, avoid);

        return (v4, v6);
    }

    /// <summary>
    /// Collects addresses that must not be allocated whatever the routing table says.
    /// </summary>
    /// <remarks>
    /// The DNS servers are reached <em>through</em> the tunnel, so taking one of their addresses would
    /// break every lookup on the machine — and this is not hypothetical, since proxy tooling parks
    /// resolvers inside the benchmarking range the first pool draws from. The server host goes in for
    /// the same reason when it is a literal. Anything outside every pool costs nothing to list.
    /// </remarks>
    private static List<IpAddr> AddressesToAvoid(SshVpnConfiguration configuration)
    {
        var avoid = new List<IpAddr>(configuration.DnsServers.Count + 1);

        foreach (var server in configuration.DnsServers)
        {
            if (TryParse(server, out var address))
            {
                avoid.Add(address);
            }
        }

        if (TryParse(configuration.Host, out var host))
        {
            avoid.Add(host);
        }

        return avoid;
    }

    private static IpAddr Resolve(
        string? configured,
        string element,
        bool wantV4,
        string host,
        IReadOnlyList<IpPrefix> claims,
        IReadOnlyList<IpAddr> avoid)
    {
        var family = wantV4 ? "IPv4" : "IPv6";

        if (configured is { Length: > 0 })
        {
            var address = ParseConfigured(configured, element, wantV4);
            Report(family, address, $"configured in <{element}>", claims);
            return address;
        }

        IpAddr allocated;
        bool exhausted;

        if (wantV4)
        {
            allocated = ClientAddressAllocator.AllocateV4(claims, avoid, out exhausted);
        }
        else
        {
            allocated = ClientAddressAllocator.AllocateV6(host, claims, avoid, out exhausted);
        }

        if (exhausted)
        {
            PluginLog.Error(
                $"Every {family} candidate is already reached by this machine, so the tunnel is "
                + $"taking {allocated.Format()} anyway; whatever else holds it becomes unreachable "
                + $"until this tunnel stops. Pin a free address in <{element}> to choose differently.");
            return allocated;
        }

        Report(family, allocated, "allocated", claims);
        return allocated;
    }

    /// <summary>
    /// Logs the address, where it came from, and what else reaches it.
    /// </summary>
    /// <remarks>
    /// Only a claim more specific than a default counts as one worth reading. A default or
    /// half-default covers every address on the machine, so it is present on nearly every connect and
    /// says nothing about this address in particular — reporting it as a collision would make the line
    /// cry wolf every time and teach whoever reads the log to skip it, which is the one thing this
    /// line cannot afford to do.
    /// </remarks>
    private static void Report(string family, IpAddr address, string provenance, IReadOnlyList<IpPrefix> claims)
    {
        var prefix = $"Tunnel {family} address {address.Format()} ({provenance})";
        var covering = MostSpecificCovering(address, claims);

        if (covering is not { } claim)
        {
            PluginLog.Info($"{prefix}; no route reaches it");
            return;
        }

        if (claim.Length < 2)
        {
            PluginLog.Info($"{prefix}; nothing more specific than {claim} reaches it");
            return;
        }

        PluginLog.Error(
            $"{prefix}; this machine already reaches it through {claim}, which will become "
            + "unreachable until this tunnel stops");
    }

    private static IpPrefix? MostSpecificCovering(IpAddr address, IReadOnlyList<IpPrefix> claims)
    {
        var host = new IpPrefix(address, address.IsV4 ? 32 : 128);
        IpPrefix? best = null;

        foreach (var claim in claims)
        {
            if (claim.Contains(host) && (best is not { } current || claim.Length > current.Length))
            {
                best = claim;
            }
        }

        return best;
    }

    /// <summary>
    /// Parses a configured address, refusing rather than guessing.
    /// </summary>
    /// <remarks>
    /// The same posture as the pinned host key and the inclusion routes: a value the user pinned and
    /// we cannot honour is refused, because substituting something else would give them a working
    /// tunnel that is not the one they asked for. The family check is not pedantry — an address of the
    /// wrong family reaches <c>Start</c>'s list for the other one, and what the platform does with it
    /// is unknown.
    /// </remarks>
    private static IpAddr ParseConfigured(string configured, string element, bool wantV4)
    {
        IpAddr address;

        try
        {
            address = IpAddr.Parse(configured);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            throw new InvalidOperationException(
                $"<{element}> is not an IP address: '{configured}'. Clear it to have one chosen.", ex);
        }

        if (address.IsV4 != wantV4)
        {
            throw new InvalidOperationException(
                $"<{element}> must be an {(wantV4 ? "IPv4" : "IPv6")} address, but '{configured}' is "
                + $"{(address.IsV4 ? "IPv4" : "IPv6")}.");
        }

        return address;
    }

    private static bool TryParse(string? text, out IpAddr address)
    {
        if (text is { Length: > 0 })
        {
            try
            {
                address = IpAddr.Parse(text);
                return true;
            }
            catch (Exception ex) when (ex is FormatException or ArgumentException)
            {
                // A host name rather than a literal, or a malformed DNS server. Neither is this
                // method's problem: one cannot collide with an address, and the other is reported
                // where it is used.
            }
        }

        address = default;
        return false;
    }
}
