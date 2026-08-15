namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// The states a flow passes through.
/// </summary>
/// <remarks>
/// A subset of RFC 793's. We only ever answer connections, never make them, so there is no
/// SYN-SENT and no simultaneous open. TIME-WAIT is absent too: both ends are on this machine, so
/// there are no stray segments from a previous incarnation to guard against.
/// </remarks>
internal enum TcpState
{
    /// <summary>No connection yet; waiting for a SYN.</summary>
    Listen,

    /// <summary>A SYN arrived and the channel is being opened. The handshake is not yet answered.</summary>
    SynReceived,

    /// <summary>Open in both directions.</summary>
    Established,

    /// <summary>The peer has finished sending; we may still be sending.</summary>
    CloseWait,

    /// <summary>We have finished sending; the peer may still be sending.</summary>
    FinWait,

    /// <summary>
    /// Both sides have finished sending and we are waiting for our own FIN to be acknowledged.
    /// </summary>
    LastAck,

    /// <summary>Finished. The flow can be forgotten.</summary>
    Closed,
}
