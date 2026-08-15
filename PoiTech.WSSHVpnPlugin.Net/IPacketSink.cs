using System;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// Where synthesised packets go on their way back to the operating system.
/// </summary>
internal interface IPacketSink
{
    /// <summary>
    /// Gets a value indicating whether a packet would be accepted right now.
    /// </summary>
    /// <value>
    /// <see langword="true"/> if there is room; otherwise, <see langword="false"/>.
    /// </value>
    /// <remarks>
    /// Must be free of side effects. It is consulted before work that would be wasted if the packet
    /// could not be delivered, and a version that reserved capacity would leak that reservation on
    /// every path which then decided not to send.
    /// </remarks>
    bool CanAccept { get; }

    /// <summary>
    /// Writes a packet.
    /// </summary>
    /// <param name="packet">The packet.</param>
    /// <returns><see langword="true"/> if it was accepted; otherwise, <see langword="false"/>.</returns>
    bool TryWrite(ReadOnlySpan<byte> packet);
}
