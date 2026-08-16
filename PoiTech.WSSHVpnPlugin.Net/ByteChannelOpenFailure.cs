namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// Why a channel open failed.
/// </summary>
/// <remarks>
/// The distinction is what a caller may conclude, and it exists for the negative cache: a refusal
/// may be remembered against the destination, a local failure must not be. Local failures include
/// the live-channel cap and the open timeout — and a single rekey pause can time out every open in
/// flight at once, so caching those would blackhole destinations that were fine, the configured
/// DNS servers first among them.
/// </remarks>
internal enum ByteChannelOpenFailure
{
    /// <summary>
    /// The server answered and said no, about this destination: its policy forbids it, or it tried
    /// to connect and could not. The verdict will hold for a while.
    /// </summary>
    Refused,

    /// <summary>
    /// The open never got a verdict about the destination — a local cap, a timeout, session
    /// trouble, or a server-side condition that is about the moment rather than the address.
    /// </summary>
    Local,
}
