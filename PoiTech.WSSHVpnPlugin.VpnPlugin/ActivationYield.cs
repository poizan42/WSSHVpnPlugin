using System;
using System.Threading;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Carries a cancel notification from the background-task plumbing to whichever event handler is
/// running, so it can finish promptly instead of being executed for ignoring it.
/// </summary>
/// <remarks>
/// <para>
/// At line rate there is essentially always a decapsulate event in flight — the doorbell rings per
/// batch, and batches are back to back. When the platform wants to deliver its periodic scheduling
/// activation, it cancels the in-flight task instance to make room; a task that does not complete
/// in response is terminated, host process and all. Measured twice at 100+ Mbit/s: two to three
/// minutes of perfect throughput, then
/// <c>"Background task ... did not complete in response to a cancel notification"</c> in the
/// background-task infrastructure log, a replacement host spawning mid-download, and the tunnel
/// dying at its healthiest. At low rates the scheduling activation always found a gap between
/// events, which is why this — and the "dead replacement host" mystery it explains — only ever
/// happened after sustained speed.
/// </para>
/// <para>
/// A window rather than a consume-once flag: the cancel targets one specific task instance, and
/// more than one handler can be in flight. Every handler that checks inside the window yields, the
/// targeted one among them, and a spurious early return costs one doorbell round trip.
/// </para>
/// </remarks>
internal static class ActivationYield
{
    /// <summary>
    /// How long handlers keep yielding after a cancel notification. Long enough that the targeted
    /// handler is certain to check within it, short next to the platform's own grace period.
    /// </summary>
    private static readonly long WindowMilliseconds = 250;

    private static long _yieldUntil;

    /// <summary>Gets a value indicating whether an in-flight handler should return promptly.</summary>
    public static bool Requested => Environment.TickCount64 < Volatile.Read(ref _yieldUntil);

    /// <summary>Opens the yield window. Called from the task's cancel notification.</summary>
    public static void Request()
    {
        Volatile.Write(ref _yieldUntil, Environment.TickCount64 + WindowMilliseconds);
    }
}
