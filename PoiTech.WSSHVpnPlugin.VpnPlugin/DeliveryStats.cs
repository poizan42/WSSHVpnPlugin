using System.Threading;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Counts what the platform's transport deliveries look like — the number the platform-owned
/// transport architecture lives or dies by.
/// </summary>
/// <remarks>
/// Deliveries are processed serially (~130 µs each measured on the datagram path), so
/// deliveries-per-second at line rate decides whether scheduling activations survive: 1500-byte
/// chunks at 100 Mbit/s are ~8,300/s and death; 64 KB chunks are ~200/s and trivial. The chunk
/// histogram is the verdict, surfaced through the periodic stack report. Permanent
/// instrumentation on this branch, not a probe.
/// </remarks>
internal static class DeliveryStats
{
    private static long _visits;
    private static long _bytes;
    private static long _maxChunk;
    private static long _chunksTiny;   // <= 1500
    private static long _chunksSmall;  // <= 8192
    private static long _chunksMid;    // <= 16384
    private static long _chunksLarge;  // <= 65536
    private static long _chunksHuge;   // > 65536

    internal static long Visits => Volatile.Read(ref _visits);

    internal static long Bytes => Volatile.Read(ref _bytes);

    /// <summary>Records one delivery of <paramref name="length"/> wire bytes.</summary>
    public static void Record(uint length)
    {
        Interlocked.Increment(ref _visits);

        if (length == 0)
        {
            return;
        }

        Interlocked.Add(ref _bytes, length);
        InterlockedMax(ref _maxChunk, length);

        if (length <= 1500)
        {
            Interlocked.Increment(ref _chunksTiny);
        }
        else if (length <= 8192)
        {
            Interlocked.Increment(ref _chunksSmall);
        }
        else if (length <= 16384)
        {
            Interlocked.Increment(ref _chunksMid);
        }
        else if (length <= 65536)
        {
            Interlocked.Increment(ref _chunksLarge);
        }
        else
        {
            Interlocked.Increment(ref _chunksHuge);
        }
    }

    /// <summary>The totals line for reports: histogram, max chunk, lifetime average.</summary>
    public static string Describe()
    {
        var visits = Volatile.Read(ref _visits);
        var bytes = Volatile.Read(ref _bytes);
        var average = visits > 0 ? bytes / visits : 0;

        return $"chunks <=1.5k/<=8k/<=16k/<=64k/>64k: {Volatile.Read(ref _chunksTiny)}/"
            + $"{Volatile.Read(ref _chunksSmall)}/{Volatile.Read(ref _chunksMid)}/"
            + $"{Volatile.Read(ref _chunksLarge)}/{Volatile.Read(ref _chunksHuge)}, "
            + $"avg {average} B, max {Volatile.Read(ref _maxChunk)} B";
    }

    private static void InterlockedMax(ref long target, long value)
    {
        long seen;
        while (value > (seen = Volatile.Read(ref target))
            && Interlocked.CompareExchange(ref target, value, seen) != seen)
        {
        }
    }
}
