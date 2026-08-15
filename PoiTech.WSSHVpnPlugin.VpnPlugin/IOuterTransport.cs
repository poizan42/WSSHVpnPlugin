using System;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// The socket handed to the platform as the outer tunnel transport, whatever shape it takes.
/// </summary>
/// <remarks>
/// Two shapes exist because it is not yet known which one the platform will accept. A loopback pair
/// carries nothing and lets us ring a doorbell to provoke a decapsulate call; a real connection to
/// the SSH server carries nothing useful either, but looks like what a control channel trigger is
/// for — a remote connection worth waking the machine for — and cannot be rung.
/// </remarks>
internal interface IOuterTransport : IDisposable
{
    /// <summary>
    /// Gets the socket to pass to <c>StartWithMainTransport</c>.
    /// </summary>
    object Transport { get; }

    /// <summary>
    /// Gets a value indicating whether <see cref="RingDoorbell"/> does anything.
    /// </summary>
    bool CanRingDoorbell { get; }

    /// <summary>
    /// Asks the platform for a decapsulate call, if this transport can.
    /// </summary>
    void RingDoorbell();
}
