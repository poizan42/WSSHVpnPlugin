using System;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// The sockets handed to the platform as the outer tunnel transports.
/// </summary>
/// <remarks>
/// One implementation remains — <see cref="PlatformOwnedTransport"/>, the real SSH TCP socket as
/// the main transport plus a loopback datagram pair as the doorbell — but the seam stays: the
/// packet path only needs "something the platform accepted at Start, with a doorbell to provoke
/// decapsulate visits", and the loopback-dummy era proved a second shape can live behind it.
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
