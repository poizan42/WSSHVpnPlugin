using System;
using System.Buffers.Binary;
using System.Net;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// An IP address of either family, as a 16-byte value.
/// </summary>
/// <remarks>
/// <para>
/// IPv4 addresses are stored in the v4-mapped form (<c>::ffff:a.b.c.d</c>), so the family is
/// derivable from the value and no discriminator field is needed - which is what keeps the struct at
/// exactly 16 bytes and makes <see langword="record"/> equality and hashing correct with no code.
/// The mapping is unambiguous because v4-mapped addresses are an in-API convention and never appear
/// as the source or destination of a packet on the wire.
/// </para>
/// <para>
/// Two <see cref="ulong"/> halves rather than a <see cref="UInt128"/>, holding the address in
/// big-endian order: <see cref="High"/> is bytes 0-7 and <see cref="Low"/> is bytes 8-15. This type
/// rides the packet path in every flow key and checksum, so its operations stay plain 64-bit
/// arithmetic; <see cref="UInt128"/> is for connect-time code like prefix math.
/// </para>
/// </remarks>
/// <param name="High">The first eight bytes of the address, big-endian.</param>
/// <param name="Low">The last eight bytes of the address, big-endian.</param>
internal readonly record struct IpAddr(ulong High, ulong Low)
{
    /// <summary>The bits of <see cref="Low"/> above a v4-mapped address.</summary>
    private const ulong V4MappedPrefix = 0x0000_FFFF_0000_0000;

    /// <summary>Gets a value indicating whether this is an IPv4 address.</summary>
    public bool IsV4 => High == 0 && (Low & 0xFFFF_FFFF_0000_0000) == V4MappedPrefix;

    /// <summary>Gets the IPv4 address, in host byte order. Only meaningful when <see cref="IsV4"/>.</summary>
    public uint V4 => (uint)Low;

    /// <summary>Gets the IP header length this address's family uses, without options or extensions.</summary>
    public int HeaderLength => IsV4 ? Ipv4Packet.MinimumHeaderLength : Ipv6Packet.HeaderLength;

    /// <summary>
    /// Wraps an IPv4 address.
    /// </summary>
    /// <param name="address">The address, in host byte order.</param>
    public static IpAddr FromV4(uint address) => new(0, V4MappedPrefix | address);

    /// <summary>
    /// Reads an IPv6 address from its wire form.
    /// </summary>
    /// <param name="bytes">The 16 address bytes.</param>
    public static IpAddr ReadV6(ReadOnlySpan<byte> bytes) => new(
        BinaryPrimitives.ReadUInt64BigEndian(bytes[..8]),
        BinaryPrimitives.ReadUInt64BigEndian(bytes[8..16]));

    /// <summary>
    /// Writes the address in IPv6 wire form.
    /// </summary>
    /// <param name="destination">The 16 bytes to write into.</param>
    public void WriteV6(Span<byte> destination)
    {
        BinaryPrimitives.WriteUInt64BigEndian(destination[..8], High);
        BinaryPrimitives.WriteUInt64BigEndian(destination[8..16], Low);
    }

    /// <summary>
    /// Parses an address of either family.
    /// </summary>
    /// <param name="text">The textual form.</param>
    /// <remarks>Allocates; for configuration and tests, not the packet path.</remarks>
    public static IpAddr Parse(string text)
    {
        var bytes = IPAddress.Parse(text).GetAddressBytes();
        return bytes.Length == 4
            ? FromV4(BinaryPrimitives.ReadUInt32BigEndian(bytes))
            : ReadV6(bytes);
    }

    /// <summary>
    /// Formats the address for logging.
    /// </summary>
    /// <remarks>Allocates; for logging, not the packet path.</remarks>
    public string Format()
    {
        if (IsV4)
        {
            return Ipv4Packet.Format(V4);
        }

        Span<byte> bytes = stackalloc byte[16];
        WriteV6(bytes);
        return new IPAddress(bytes).ToString();
    }

    /// <summary>
    /// Formats the address and a port for logging, bracketing IPv6 so the port is unambiguous.
    /// </summary>
    /// <param name="port">The port.</param>
    /// <remarks>Allocates; for logging, not the packet path.</remarks>
    public string FormatEndpoint(ushort port)
        => IsV4 ? $"{Format()}:{port}" : $"[{Format()}]:{port}";
}
