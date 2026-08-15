using System;
using System.Buffers.Binary;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// The internet checksum of RFC 1071: the one's complement of the one's complement sum.
/// </summary>
internal static class InternetChecksum
{
    /// <summary>
    /// Computes the checksum of a block.
    /// </summary>
    /// <param name="data">The bytes to sum.</param>
    /// <returns>The checksum, in host byte order.</returns>
    public static ushort Compute(ReadOnlySpan<byte> data)
    {
        return Finish(Accumulate(0, data));
    }

    /// <summary>
    /// Adds a block to a running sum.
    /// </summary>
    /// <param name="sum">The running sum.</param>
    /// <param name="data">The bytes to add.</param>
    /// <returns>The updated running sum, not yet folded or complemented.</returns>
    /// <remarks>
    /// Kept separate from <see cref="Finish"/> so that a TCP checksum can cover the pseudo-header
    /// and the segment without copying them into one buffer first.
    /// </remarks>
    public static uint Accumulate(uint sum, ReadOnlySpan<byte> data)
    {
        while (data.Length >= 2)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(data);
            data = data[2..];
        }

        if (data.Length == 1)
        {
            // An odd trailing byte is padded on the right, not the left.
            sum += (uint)(data[0] << 8);
        }

        return sum;
    }

    /// <summary>
    /// Folds the carries out of a running sum and complements it.
    /// </summary>
    /// <param name="sum">The running sum.</param>
    /// <returns>The checksum.</returns>
    public static ushort Finish(uint sum)
    {
        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)~sum;
    }
}
