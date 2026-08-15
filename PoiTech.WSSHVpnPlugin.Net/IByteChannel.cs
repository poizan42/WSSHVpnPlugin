using System;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// The outbound half of a flow: a byte stream to somewhere, with no framing.
/// </summary>
/// <remarks>
/// This is the seam that keeps SSH out of the stack. In production it is an SSH
/// <c>direct-tcpip</c> channel; in tests it is a fake that records what it was given, which is what
/// lets the whole stack be driven from synthetic packets with no session, no server and no threads.
/// </remarks>
internal interface IByteChannel : IDisposable
{
    /// <summary>Gets a value indicating whether the channel is still usable.</summary>
    bool IsOpen { get; }

    /// <summary>Gets a value indicating whether the far end has finished sending.</summary>
    bool IsPeerEof { get; }

    /// <summary>
    /// Peeks at received bytes without consuming them.
    /// </summary>
    /// <param name="data">Receives the bytes, valid until <see cref="Advance"/>.</param>
    /// <returns><see langword="true"/> if there was anything to read.</returns>
    bool TryRead(out ArraySegment<byte> data);

    /// <summary>
    /// Releases bytes previously peeked, once they are safely delivered.
    /// </summary>
    /// <param name="count">The number of bytes to release.</param>
    /// <returns><see langword="true"/> if a window credit flush is now due.</returns>
    bool Advance(int count);

    /// <summary>Sends any window credit that <see cref="Advance"/> has accumulated.</summary>
    void FlushWindowCredit();

    /// <summary>
    /// Sends what the far end's window allows, without waiting.
    /// </summary>
    /// <param name="data">The buffer to send from.</param>
    /// <param name="offset">The offset to start at.</param>
    /// <param name="count">The number of bytes to send.</param>
    /// <param name="written">Receives how many bytes were actually sent.</param>
    /// <returns>The outcome.</returns>
    ByteChannelSendResult TrySend(byte[] data, int offset, int count, out int written);

    /// <summary>Signals that this side will send no more.</summary>
    void SendEof();
}
