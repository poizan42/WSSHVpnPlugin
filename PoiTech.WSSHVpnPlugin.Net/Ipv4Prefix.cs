using System;
using System.Collections.Generic;
using System.Globalization;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// An IPv4 CIDR prefix, and the prefix arithmetic that turns "route everything except these" into a
/// list of routes the VPN platform will actually honour.
/// </summary>
/// <remarks>
/// <para>
/// This exists because <em>route-based exclusion does not work</em>. Both knobs the platform offers
/// for it — <c>VpnRouteAssignment.Ipv4ExclusionRoutes</c> and <c>ExcludeLocalSubnets</c> — are
/// accepted without complaint and change nothing: with the client's own LAN excluded, a route lookup
/// for a host in that range still returns the tunnel interface and the tunnel's source address, even
/// though the physical NIC holds an on-link route for the same subnet that is both more specific and
/// better-metric. Something above the routing table redirects, so reading the table tells you the
/// opposite of what happens.
/// </para>
/// <para>
/// What the platform does honour is the inclusion list, because that is how the tunnel gets any
/// traffic at all. So an exclusion is expressed by <em>omission</em>: subtract the excluded prefixes
/// from the inclusion set and pass the remainder. The tunnel then has no route covering an excluded
/// range and the physical interface's own route — an on-link subnet, or its default route — wins on
/// the ordinary rules.
/// </para>
/// <para>
/// Omission generalises where the alternatives do not. A traffic filter carrying
/// <c>RoutingPolicyType.SplitRouting</c> is documented as letting the networking stack decide, which
/// only helps for a range that already has a better route somewhere else — an on-link subnet. For a
/// range on the far side of the internet the stack's answer is still the tunnel, because the
/// half-default pair (<c>0.0.0.0/1</c> plus <c>128.0.0.0/1</c>) beats the physical interface's
/// <c>0.0.0.0/0</c> on prefix length, which is the whole reason that pair is used. Subtracting the
/// range removes the route that was winning, so it works either way.
/// </para>
/// </remarks>
internal readonly struct Ipv4Prefix : IEquatable<Ipv4Prefix>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Ipv4Prefix"/> struct, masking host bits off.
    /// </summary>
    /// <param name="address">The address, in host byte order.</param>
    /// <param name="length">The prefix length, 0 to 32.</param>
    public Ipv4Prefix(uint address, int length)
    {
        if (length is < 0 or > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(length), length, "A prefix length must be 0 to 32.");
        }

        Length = (byte)length;
        Network = address & MaskFor(length);
    }

    /// <summary>Gets the network address, in host byte order, with host bits cleared.</summary>
    public uint Network { get; }

    /// <summary>Gets the prefix length.</summary>
    public byte Length { get; }

    /// <summary>Gets the last address covered, in host byte order.</summary>
    public uint Last => Network | ~MaskFor(Length);

    /// <summary>
    /// Parses CIDR notation, or a bare address as a <c>/32</c>.
    /// </summary>
    /// <param name="value">Text such as <c>10.0.0.0/8</c> or <c>192.0.2.1</c>.</param>
    /// <returns>The prefix.</returns>
    /// <exception cref="FormatException">The text is not a prefix.</exception>
    /// <remarks>
    /// A bare address means <c>/32</c> to match the plug-in's own route parser, so the same
    /// configuration strings work in both places.
    /// </remarks>
    public static Ipv4Prefix Parse(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var text = value.Trim();
        var slash = text.IndexOf('/', StringComparison.Ordinal);
        var addressText = slash < 0 ? text : text[..slash];
        var length = 32;

        if (slash >= 0)
        {
            var lengthText = text[(slash + 1)..];
            if (!int.TryParse(lengthText, NumberStyles.None, CultureInfo.InvariantCulture, out length) || length > 32)
            {
                throw new FormatException($"'{value}' is not a valid prefix: the prefix length is not 0 to 32.");
            }
        }

        return new Ipv4Prefix(ParseAddress(addressText, value), length);
    }

    /// <summary>
    /// Gets a value indicating whether this prefix wholly contains another.
    /// </summary>
    /// <param name="other">The prefix to test.</param>
    /// <returns><see langword="true"/> if every address of <paramref name="other"/> is covered.</returns>
    public bool Contains(Ipv4Prefix other)
    {
        return Length <= other.Length && (other.Network & MaskFor(Length)) == Network;
    }

    /// <summary>
    /// Gets a value indicating whether the two prefixes share any address.
    /// </summary>
    /// <param name="other">The prefix to test.</param>
    /// <returns><see langword="true"/> if they overlap at all.</returns>
    /// <remarks>
    /// Two prefixes are either disjoint or one contains the other — there is no partial overlap —
    /// which is what makes the subtraction below a simple recursion.
    /// </remarks>
    public bool Overlaps(Ipv4Prefix other)
    {
        return Contains(other) || other.Contains(this);
    }

    /// <summary>
    /// Subtracts a set of prefixes from another, returning the cover of what is left.
    /// </summary>
    /// <param name="included">The prefixes to keep.</param>
    /// <param name="excluded">The prefixes to remove.</param>
    /// <returns>
    /// The prefixes covering exactly the addresses in <paramref name="included"/> and not in
    /// <paramref name="excluded"/>, ordered by network address. Empty if the exclusions cover
    /// everything — which a caller assigning tunnel routes must treat as a configuration error
    /// rather than pass on, since a tunnel with no routes carries nothing.
    /// </returns>
    /// <remarks>
    /// Halve and recurse: a prefix that touches no exclusion survives whole, one wholly inside an
    /// exclusion disappears, and anything else splits into two half-length prefixes that are each
    /// decided the same way. Recursion is bounded by <c>/32</c>, and the result is minimal — two
    /// sibling halves can never both survive, because if neither met an exclusion their parent would
    /// have survived intact and never been split.
    /// </remarks>
    public static IReadOnlyList<Ipv4Prefix> Subtract(
        IEnumerable<Ipv4Prefix> included,
        IEnumerable<Ipv4Prefix> excluded)
    {
        ArgumentNullException.ThrowIfNull(included);
        ArgumentNullException.ThrowIfNull(excluded);

        var holes = new List<Ipv4Prefix>(excluded);
        var kept = new List<Ipv4Prefix>();

        foreach (var prefix in included)
        {
            SubtractInto(prefix, holes, kept);
        }

        kept.Sort(static (left, right) => left.Network != right.Network
            ? left.Network.CompareTo(right.Network)
            : left.Length.CompareTo(right.Length));

        return kept;
    }

    /// <inheritdoc/>
    public bool Equals(Ipv4Prefix other)
    {
        return Network == other.Network && Length == other.Length;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is Ipv4Prefix other && Equals(other);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Network, Length);
    }

    /// <inheritdoc/>
    public override string ToString()
    {
        return string.Format(
            CultureInfo.InvariantCulture,
            "{0}.{1}.{2}.{3}/{4}",
            (Network >> 24) & 0xFF,
            (Network >> 16) & 0xFF,
            (Network >> 8) & 0xFF,
            Network & 0xFF,
            Length);
    }

    /// <summary>
    /// Gets the address text without the prefix length, for callers building platform route objects.
    /// </summary>
    /// <returns>Dotted-quad text.</returns>
    public string ToAddressString()
    {
        var text = ToString();
        return text[..text.IndexOf('/', StringComparison.Ordinal)];
    }

    private static uint MaskFor(int length)
    {
        return length == 0 ? 0u : uint.MaxValue << (32 - length);
    }

    private static uint ParseAddress(string text, string original)
    {
        var octets = text.Split('.');
        if (octets.Length != 4)
        {
            throw new FormatException($"'{original}' is not a valid prefix: expected four dot-separated octets.");
        }

        uint address = 0;
        foreach (var octet in octets)
        {
            if (!byte.TryParse(octet, NumberStyles.None, CultureInfo.InvariantCulture, out var value))
            {
                throw new FormatException($"'{original}' is not a valid prefix: '{octet}' is not an octet.");
            }

            address = (address << 8) | value;
        }

        return address;
    }

    private static void SubtractInto(Ipv4Prefix prefix, List<Ipv4Prefix> holes, List<Ipv4Prefix> kept)
    {
        var touched = false;

        foreach (var hole in holes)
        {
            if (hole.Contains(prefix))
            {
                // Wholly excluded: nothing of this prefix survives, and splitting it would only
                // rediscover that 2^n times over.
                return;
            }

            if (prefix.Contains(hole))
            {
                touched = true;
            }
        }

        if (!touched)
        {
            kept.Add(prefix);
            return;
        }

        // A hole strictly inside this prefix, so the prefix is too coarse to describe what is left.
        // It cannot already be a /32: a /32 that contained a hole would have been contained by it.
        var half = (byte)(prefix.Length + 1);
        SubtractInto(new Ipv4Prefix(prefix.Network, half), holes, kept);
        SubtractInto(new Ipv4Prefix(prefix.Network | (1u << (32 - half)), half), holes, kept);
    }
}
