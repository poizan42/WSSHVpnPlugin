using System;
using System.Globalization;
using System.Threading;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Networking.Vpn;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// A real, idle TCP connection to the SSH server, handed to the platform as the outer tunnel
/// transport.
/// </summary>
/// <remarks>
/// <para>
/// Kept only as a diagnostic alternative to <see cref="LoopbackTransport"/>. It was written to test
/// whether the platform would accept a transport connected to a real remote server, on the theory
/// that a control channel trigger exists to keep a <em>remote</em> connection alive and might refuse
/// a loopback pair with no remote end to wake for. **It made no difference** — both shapes fail and
/// succeed identically, and the real cause was an empty assigned IPv6 address list. Prefer the
/// loopback shape, which can ring a doorbell.
/// </para>
/// <para>
/// The connection is deliberately wasted. SSH runs on a socket of its own; this one exists only for
/// the platform to own, read and poll. The server will send an identification string, which the
/// platform's reader will consume and discard, and nothing will ever reply — an idle connection an
/// SSH server will eventually time out, which is itself something the spike needs to observe.
/// </para>
/// <para>
/// The cost is the doorbell: inbound injection is provoked by writing to the socket the platform
/// reads, and we cannot write to this one on the platform's behalf. So if this shape is what starts
/// the channel, inbound packets need the worker-thread append path instead — which is exactly what
/// the spike's last probe measures.
/// </para>
/// </remarks>
internal sealed class RemoteDummyTransport : IOuterTransport
{
    private readonly StreamSocket _transport;
    private int _disposed;

    private RemoteDummyTransport(StreamSocket transport)
    {
        _transport = transport;
    }

    /// <inheritdoc/>
    public object Transport
    {
        get { return _transport; }
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
    /// Same ordering rule as the loopback shape, and for the same reason: associate first, on an
    /// unconnected socket, because that is what records the transport in the channel and what
    /// <c>StartWithMainTransport</c> checks against.
    /// </remarks>
    public static RemoteDummyTransport Create(VpnChannel channel, string host, uint port)
    {
        ArgumentNullException.ThrowIfNull(channel);

        var transport = new StreamSocket();
        try
        {
            channel.AssociateTransport(transport, null);

            transport.ConnectAsync(
                new HostName(host),
                port.ToString(CultureInfo.InvariantCulture))
                .AsTask()
                .GetAwaiter()
                .GetResult();

            PluginLog.Info($"Remote dummy transport connected to {host}:{port} (carries nothing)");
            return new RemoteDummyTransport(transport);
        }
        catch
        {
            transport.Dispose();
            throw;
        }
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Nothing to ring: the platform reads the far end of a real connection, and we are not the far
    /// end. Logged once rather than silently, so a stalled inbound queue is not a mystery.
    /// </remarks>
    public void RingDoorbell()
    {
        PluginLog.Error(
            "Cannot ring a doorbell on a remote dummy transport; inbound injection needs the "
            + "worker-thread append path with this shape.");
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
            _transport.Dispose();
        }
        catch (Exception ex)
        {
            PluginLog.Error("Failed to close the remote dummy transport cleanly", ex);
        }
    }
}
