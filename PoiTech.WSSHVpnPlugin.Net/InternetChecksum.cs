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
        ulong total = sum;

        // Eight bytes per step rather than two. RFC 1071's sum is congruent mod 2^16-1 whatever
        // the word size - 2^64 = 1 (mod 2^16-1) - so 64-bit chunks added with end-around carry
        // reach the same folded value the 16-bit loop did, at a quarter of the reads. This loop
        // was the stack thread's single largest CPU cost, sampled live at 60+ Mbit/s: one 16-bit
        // big-endian read per word, ~680 of them per packet.
        while (data.Length >= 8)
        {
            var chunk = BinaryPrimitives.ReadUInt64BigEndian(data);
            total += chunk;

            if (total < chunk)
            {
                total++;
            }

            data = data[8..];
        }

        while (data.Length >= 2)
        {
            total += BinaryPrimitives.ReadUInt16BigEndian(data);
            data = data[2..];
        }

        if (data.Length == 1)
        {
            // An odd trailing byte is padded on the right, not the left.
            total += (uint)(data[0] << 8);
        }

        // Folded back to 32 bits - congruence is preserved, 2^16-1 divides 2^32-1 - so the running
        // sum keeps the shape the next block and Finish expect.
        while ((total >> 32) != 0)
        {
            total = (total & 0xFFFFFFFF) + (total >> 32);
        }

        return (uint)total;
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
