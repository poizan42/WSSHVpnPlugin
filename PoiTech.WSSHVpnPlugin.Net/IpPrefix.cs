using System;
using System.Collections.Generic;
using System.Globalization;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// A CIDR prefix of either family, and the prefix arithmetic that turns "route everything except
/// these" into a list of routes the VPN platform will actually honour.
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
/// half-default pair (<c>0.0.0.0/1</c> plus <c>128.0.0.0/1</c>, or their v6 twins <c>::/1</c> plus
/// <c>8000::/1</c>) beats the physical interface's default on prefix length, which is the whole
/// reason those pairs are used. Subtracting the range removes the route that was winning, so it
/// works either way.
/// </para>
/// <para>
/// The two families are disjoint spaces, exactly as they are in a routing table: a prefix never
/// contains, overlaps or splits one of the other family, so a v6 hole passes through a v4 inclusion
/// list without touching it. Callers still partition by family, because the platform takes the two
/// route lists separately.
/// </para>
/// </remarks>
internal readonly struct IpPrefix : IEquatable<IpPrefix>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="IpPrefix"/> struct, masking host bits off.
    /// </summary>
    /// <param name="address">The address whose family sets the prefix's width.</param>
    /// <param name="length">The prefix length, 0 to 32 or 0 to 128 by family.</param>
    public IpPrefix(IpAddr address, int length)
    {
        var width = address.IsV4 ? 32 : 128;

        if (length < 0 || length > width)
        {
            throw new ArgumentOutOfRangeException(
                nameof(length), length, $"A prefix length must be 0 to {width} for this family.");
        }

        Length = (byte)length;
        Network = FromValue(ValueOf(address) & MaskFor(width, length), address.IsV4);
    }

    /// <summary>Gets the network address, with host bits cleared.</summary>
    public IpAddr Network { get; }

    /// <summary>Gets the prefix length.</summary>
    public byte Length { get; }

    /// <summary>Gets a value indicating whether this is an IPv4 prefix.</summary>
    public bool IsV4 => Network.IsV4;

    /// <summary>Gets the last address covered.</summary>
    public IpAddr Last
    {
        get
        {
            var width = Width;
            var all = AllOnes(width);
            return FromValue(ValueOf(Network) | (~MaskFor(width, Length) & all), IsV4);
        }
    }

    private int Width => IsV4 ? 32 : 128;

    /// <summary>
    /// Parses CIDR notation of either family, or a bare address as a host route.
    /// </summary>
    /// <param name="value">Text such as <c>10.0.0.0/8</c>, <c>192.0.2.1</c> or <c>2001:db8::/32</c>.</param>
    /// <returns>The prefix.</returns>
    /// <exception cref="FormatException">The text is not a prefix.</exception>
    /// <remarks>
    /// The family is the text's: a colon means IPv6, otherwise strictly four dot-separated octets —
    /// the v4 grammar is deliberately no looser than it ever was, so existing configuration strings
    /// parse identically. A bare address means <c>/32</c> or <c>/128</c> to match the plug-in's own
    /// route handling. The v4-mapped text form (<c>::ffff:a.b.c.d</c>) is rejected rather than
    /// guessed at: it names a v4 address in v6 clothes, so neither family's prefix length would
    /// clearly apply.
    /// </remarks>
    public static IpPrefix Parse(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var text = value.Trim();
        var slash = text.IndexOf('/', StringComparison.Ordinal);
        var addressText = slash < 0 ? text : text[..slash];
        var isV6 = addressText.Contains(':', StringComparison.Ordinal);
        var width = isV6 ? 128 : 32;
        var length = width;

        if (slash >= 0)
        {
            var lengthText = text[(slash + 1)..];
            if (!int.TryParse(lengthText, NumberStyles.None, CultureInfo.InvariantCulture, out length) || length > width)
            {
                throw new FormatException($"'{value}' is not a valid prefix: the prefix length is not 0 to {width}.");
            }
        }

        if (!isV6)
        {
            return new IpPrefix(IpAddr.FromV4(ParseV4Address(addressText, value)), length);
        }

        IpAddr address;
        try
        {
            address = IpAddr.Parse(addressText);
        }
        catch (FormatException)
        {
            throw new FormatException($"'{value}' is not a valid prefix: '{addressText}' is not an address.");
        }

        if (address.IsV4)
        {
            throw new FormatException(
                $"'{value}' is not a valid prefix: write a v4-mapped address in its IPv4 form.");
        }

        return new IpPrefix(address, length);
    }

    /// <summary>
    /// Gets a value indicating whether this prefix wholly contains another.
    /// </summary>
    /// <param name="other">The prefix to test.</param>
    /// <returns><see langword="true"/> if every address of <paramref name="other"/> is covered.</returns>
    public bool Contains(IpPrefix other)
    {
        if (IsV4 != other.IsV4)
        {
            return false;
        }

        return Length <= other.Length
            && (ValueOf(other.Network) & MaskFor(Width, Length)) == ValueOf(Network);
    }

    /// <summary>
    /// Gets a value indicating whether the two prefixes share any address.
    /// </summary>
    /// <param name="other">The prefix to test.</param>
    /// <returns><see langword="true"/> if they overlap at all.</returns>
    /// <remarks>
    /// Two prefixes of one family are either disjoint or one contains the other — there is no
    /// partial overlap — which is what makes the subtraction below a simple recursion.
    /// </remarks>
    public bool Overlaps(IpPrefix other)
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
    /// <paramref name="excluded"/>, v4 before v6 and ordered by network address within each family.
    /// Empty if the exclusions cover everything — which a caller assigning tunnel routes must treat
    /// as a configuration error rather than pass on, since a tunnel with no routes carries nothing.
    /// </returns>
    /// <remarks>
    /// Halve and recurse: a prefix that touches no exclusion survives whole, one wholly inside an
    /// exclusion disappears, and anything else splits into two half-length prefixes that are each
    /// decided the same way. Recursion is bounded by the family's width, and the result is minimal —
    /// two sibling halves can never both survive, because if neither met an exclusion their parent
    /// would have survived intact and never been split.
    /// </remarks>
    public static IReadOnlyList<IpPrefix> Subtract(
        IEnumerable<IpPrefix> included,
        IEnumerable<IpPrefix> excluded)
    {
        ArgumentNullException.ThrowIfNull(included);
        ArgumentNullException.ThrowIfNull(excluded);

        var holes = new List<IpPrefix>(excluded);
        var kept = new List<IpPrefix>();

        foreach (var prefix in included)
        {
            SubtractInto(prefix, holes, kept);
        }

        kept.Sort(static (left, right) =>
        {
            if (left.IsV4 != right.IsV4)
            {
                return left.IsV4 ? -1 : 1;
            }

            var networks = ValueOf(left.Network).CompareTo(ValueOf(right.Network));
            return networks != 0 ? networks : left.Length.CompareTo(right.Length);
        });

        return kept;
    }

    /// <inheritdoc/>
    public bool Equals(IpPrefix other)
    {
        return Network == other.Network && Length == other.Length;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is IpPrefix other && Equals(other);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Network, Length);
    }

    /// <inheritdoc/>
    public override string ToString()
    {
        return string.Create(CultureInfo.InvariantCulture, $"{Network.Format()}/{Length}");
    }

    /// <summary>
    /// Gets the address text without the prefix length, for callers building platform route objects.
    /// </summary>
    public string ToAddressString()
    {
        return Network.Format();
    }

    private static UInt128 ValueOf(IpAddr address)
    {
        return address.IsV4 ? address.V4 : ((UInt128)address.High << 64) | address.Low;
    }

    private static IpAddr FromValue(UInt128 value, bool isV4)
    {
        return isV4 ? IpAddr.FromV4((uint)value) : new IpAddr((ulong)(value >> 64), (ulong)value);
    }

    private static UInt128 AllOnes(int width)
    {
        return width == 128 ? UInt128.MaxValue : (((UInt128)1 << width) - 1);
    }

    private static UInt128 MaskFor(int width, int length)
    {
        return length == 0 ? 0 : (AllOnes(width) << (width - length)) & AllOnes(width);
    }

    private static uint ParseV4Address(string text, string original)
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

    private static void SubtractInto(IpPrefix prefix, List<IpPrefix> holes, List<IpPrefix> kept)
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
        // It cannot already be a host route: one that contained a hole would have been contained by
        // it.
        var width = prefix.Width;
        var half = prefix.Length + 1;
        var sibling = ValueOf(prefix.Network) | ((UInt128)1 << (width - half));
        SubtractInto(new IpPrefix(prefix.Network, half), holes, kept);
        SubtractInto(new IpPrefix(FromValue(sibling, prefix.IsV4), half), holes, kept);
    }
}
