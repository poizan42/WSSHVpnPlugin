using System;
using System.Threading;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Networking.Vpn;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// The real SSH TCP socket, handed to the platform as the outer tunnel transport it owns.
/// </summary>
/// <remarks>
/// <para>
/// The platform-owned-transport architecture: <c>AssociateTransport</c> takes the unconnected
/// front socket, the socket is then connected to the SSH server, and after <c>Start*</c> the VPN
/// service reads and writes it itself. Wire bytes reach SSH.NET through <c>Decapsulate</c> and a
/// <c>PipeSshTransport</c>; outgoing wire bytes leave through <see cref="Send"/> — the
/// out-of-band <c>IVpnChannel5</c> append/flush lane, proven to transmit immediately and preserve
/// order under concurrency (probes 1–2 in docs/experiments/platform-owned-transport.md).
/// </para>
/// <para>
/// The socket is deliberately not source-bound: pinning the outer flow out of the tunnel after
/// <c>TakeTransportOwnership</c> is the platform's job, and whether it does it is one of the
/// things this architecture verifies. <c>NoDelay</c> must be set before <c>AssociateTransport</c>
/// — associate locks the socket's control interface (established by the TCP-loopback attempt's
/// invalid-state throw).
/// </para>
/// <para>
/// No doorbell yet: <see cref="RingDoorbell"/> is a no-op, so inbound injection rides the
/// data-driven decapsulate visits, which are continuous during any actual traffic. The second
/// transport that restores the doorbell is the next phase.
/// </para>
/// </remarks>
internal sealed class PlatformOwnedTransport : IOuterTransport
{
    private readonly StreamSocket _front;
    private readonly object _sendGate = new();

    /// <summary>Owned <c>IVpnChannel2</c> — the send-buffer pool.</summary>
    private IntPtr _channel2;

    /// <summary>Owned <c>IVpnChannel5</c> — the append/flush lane.</summary>
    private IntPtr _channel5;

    private int _disposed;

    private PlatformOwnedTransport(StreamSocket front, IntPtr channel2, IntPtr channel5)
    {
        _front = front;
        _channel2 = channel2;
        _channel5 = channel5;
    }

    /// <inheritdoc/>
    public object Transport
    {
        get { return _front; }
    }

    /// <inheritdoc/>
    public bool CanRingDoorbell
    {
        get { return false; }
    }

    /// <summary>
    /// Associates a fresh socket with the channel and connects it to the SSH server.
    /// </summary>
    /// <remarks>
    /// The channel interface QIs come first: they double as the connect-time self-check that the
    /// <c>IVpnChannel5</c> IID and this Windows build agree, failing the connect loudly before
    /// anything touches the network.
    /// </remarks>
    public static PlatformOwnedTransport Create(VpnChannel channel, SshVpnConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentNullException.ThrowIfNull(configuration);

        var hr = VpnChannelAbi.GetChannel2(channel, out var channel2);
        if (hr < 0)
        {
            throw VpnChannelAbi.FailureFor(hr, "QueryInterface(IVpnChannel2)");
        }

        hr = VpnChannelAbi.GetChannel5(channel, out var channel5);
        if (hr < 0)
        {
            VpnChannelAbi.Release(channel2);
            throw VpnChannelAbi.FailureFor(hr, "QueryInterface(IVpnChannel5)");
        }

        var front = new StreamSocket();

        try
        {
            front.Control.NoDelay = true;

            channel.AssociateTransport(front, null);

            front.ConnectAsync(
                    new HostName(configuration.Host),
                    configuration.Port.ToString(System.Globalization.CultureInfo.InvariantCulture))
                .AsTask().GetAwaiter().GetResult();

            PluginLog.Info(
                $"Platform-owned transport connected to {configuration.Host}:{configuration.Port}; "
                + "the platform takes ownership at Start.");

            return new PlatformOwnedTransport(front, channel2, channel5);
        }
        catch
        {
            front.Dispose();
            VpnChannelAbi.Release(channel5);
            VpnChannelAbi.Release(channel2);
            throw;
        }
    }

    /// <summary>
    /// Puts outgoing SSH wire bytes on the platform-owned transport.
    /// </summary>
    /// <remarks>
    /// The send delegate handed to <c>PipeSshTransport</c>. Chunks at the send-pool buffer
    /// capacity (the Start frame size), appends each chunk and flushes once — probe 2 established
    /// that append order is transmit order, intra-flush and across sequential flushes. The
    /// session already serializes writers; the gate is belt on top of braces. Zero WinRT objects
    /// per call.
    /// </remarks>
    public unsafe void Send(ReadOnlySpan<byte> bytes)
    {
        lock (_sendGate)
        {
            // Checked under the gate: Dispose zeroes the channel pointers under the same gate, so
            // a send racing teardown fails here instead of dereferencing a released interface.
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

            while (!bytes.IsEmpty)
            {
                var hr = VpnChannelAbi.GetSendBuffer(_channel2, out var packet);
                if (hr < 0)
                {
                    throw VpnChannelAbi.FailureFor(hr, "GetVpnSendPacketBuffer");
                }

                try
                {
                    hr = VpnChannelAbi.AcquireSpan(packet, out var buffer, out var byteAccess, out var data, out var capacity);
                    if (hr < 0)
                    {
                        throw VpnChannelAbi.FailureFor(hr, "resolving a send buffer to its bytes");
                    }

                    int chunk;
                    unsafe
                    {
                        chunk = (int)Math.Min(bytes.Length, capacity);
                        bytes[..chunk].CopyTo(new Span<byte>(data, chunk));
                    }

                    hr = VpnChannelAbi.SetLength(buffer, (uint)chunk);
                    VpnChannelAbi.ReleaseSpan(buffer, byteAccess);

                    if (hr < 0)
                    {
                        throw VpnChannelAbi.FailureFor(hr, "put_Length on a send buffer");
                    }

                    hr = VpnChannelAbi.AppendSendBuffer(_channel5, packet);
                    if (hr < 0)
                    {
                        throw VpnChannelAbi.FailureFor(hr, "AppendVpnSendPacketBuffer");
                    }

                    bytes = bytes[chunk..];
                }
                finally
                {
                    // Append copies - the channel takes its own reference - so ours is released
                    // on every path; on failure we hold the sole reference.
                    VpnChannelAbi.Release(packet);
                }
            }

            var flush = VpnChannelAbi.FlushSendBuffers(_channel5);
            if (flush < 0)
            {
                throw VpnChannelAbi.FailureFor(flush, "FlushVpnSendPacketBuffers");
            }
        }
    }

    /// <inheritdoc/>
    public void RingDoorbell()
    {
        // No doorbell on this transport yet; injection rides data-driven decapsulate visits.
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            lock (_sendGate)
            {
                VpnChannelAbi.Release(Interlocked.Exchange(ref _channel5, default));
                VpnChannelAbi.Release(Interlocked.Exchange(ref _channel2, default));
            }

            // The socket belongs to the platform once the channel started; disposing our
            // reference is all we can do about it either way.
            _front.Dispose();
        }
        catch (Exception ex)
        {
            PluginLog.Error("Failed to close the platform-owned transport cleanly", ex);
        }
    }
}
