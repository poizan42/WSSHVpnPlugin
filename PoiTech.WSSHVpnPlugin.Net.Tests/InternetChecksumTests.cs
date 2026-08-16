using System;
using System.Buffers.Binary;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.Net.Tests;

/// <summary>
/// The fast checksum must agree with the definitional one on every length and every carry shape.
/// </summary>
/// <remarks>
/// The production loop sums 64-bit chunks with end-around carry, which is only correct because
/// RFC 1071's sum is congruent mod 2^16-1 at any word size. The reference here is the naive
/// 16-bit-word implementation the code shipped with - slow and obviously right.
/// </remarks>
[TestClass]
public class InternetChecksumTests
{
    private static ushort Reference(ReadOnlySpan<byte> data)
    {
        uint sum = 0;

        while (data.Length >= 2)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(data);
            data = data[2..];
        }

        if (data.Length == 1)
        {
            sum += (uint)(data[0] << 8);
        }

        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)~sum;
    }

    [TestMethod]
    public void AgreesWithTheDefinition_OnEveryLengthAndAlignment()
    {
        // Deterministic but irregular content, all lengths through several chunk boundaries, so
        // every remainder shape (0-7 bytes past the last full chunk, including the odd tail) and
        // plenty of carries are exercised.
        var random = new Random(1071);

        for (var length = 0; length <= 64; length++)
        {
            var data = new byte[length];
            random.NextBytes(data);

            Assert.AreEqual(Reference(data), InternetChecksum.Compute(data), $"length {length}");
        }
    }

    [TestMethod]
    public void AgreesWithTheDefinition_WhenEveryAdditionCarries()
    {
        // All-0xFF data is the worst case for the end-around carry: every 64-bit addition wraps.
        var data = new byte[1360];
        data.AsSpan().Fill(0xFF);

        Assert.AreEqual(Reference(data), InternetChecksum.Compute(data));

        // And at packet size with real-looking content.
        var random = new Random(1360);
        random.NextBytes(data);
        Assert.AreEqual(Reference(data), InternetChecksum.Compute(data));
    }

    [TestMethod]
    public void AccumulatingInBlocks_MatchesOneBlock()
    {
        // The TCP checksum chains Accumulate across the pseudo-header and the segment; the running
        // sum's shape between calls has to survive the fast path's folding.
        var random = new Random(7766);
        var data = new byte[97];
        random.NextBytes(data);

        var chained = InternetChecksum.Accumulate(0, data.AsSpan(0, 12));
        chained = InternetChecksum.Accumulate(chained, data.AsSpan(12));

        Assert.AreEqual(InternetChecksum.Compute(data), InternetChecksum.Finish(chained));
    }
}
