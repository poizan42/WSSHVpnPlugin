namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// The outcome of a non-blocking send on an <see cref="IByteChannel"/>.
/// </summary>
internal enum ByteChannelSendResult
{
    /// <summary>All of the data was sent.</summary>
    Written,

    /// <summary>The far end's window ran out; part or none of the data was sent.</summary>
    Full,

    /// <summary>The channel is closed and nothing more can be sent.</summary>
    Closed,
}
