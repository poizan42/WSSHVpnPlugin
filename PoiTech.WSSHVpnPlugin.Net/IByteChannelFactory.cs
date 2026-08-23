using System;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// Opens a byte channel to a destination.
/// </summary>
/// <remarks>
/// Opening is a round trip in production, so it is asynchronous from the stack's point of view: the
/// flow waits until the channel reports itself open, and only then is the handshake answered.
/// Accepting a connection we cannot serve would be worse than making the peer wait for it.
/// </remarks>
internal interface IByteChannelFactory
{
    /// <summary>
    /// Begins opening a channel.
    /// </summary>
    /// <param name="address">The destination address.</param>
    /// <param name="port">The destination port.</param>
    /// <param name="onOpened">Called with the channel once it is open.</param>
    /// <param name="onFailed">Called with why, if it could not be opened.</param>
    void BeginOpen(IpAddr address, ushort port, Action<IByteChannel> onOpened, Action<ByteChannelOpenFailure> onFailed);
}
