using System;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// The stack's notion of time.
/// </summary>
/// <remarks>
/// Injected so tests can advance time by hand instead of sleeping. Retransmission timeouts and
/// delayed acknowledgements are measured in hundreds of milliseconds, and a suite that waited for
/// them in real time would take minutes and still be flaky.
/// </remarks>
internal interface IStackClock
{
    /// <summary>Gets the current time, from an arbitrary origin, and monotonic.</summary>
    TimeSpan Now { get; }
}
