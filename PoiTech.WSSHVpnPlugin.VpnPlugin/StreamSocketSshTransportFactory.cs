using System;
using System.Threading;
using System.Threading.Tasks;
using Renci.SshNet.Connection;
using Windows.Networking.Sockets;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Supplies SSH.NET with a <see cref="StreamSocket"/>-backed transport, and keeps hold of the socket
/// so it can be handed to the VPN platform as the outer tunnel transport.
/// </summary>
internal sealed class StreamSocketSshTransportFactory : ISshTransportFactory
{
    private StreamSocketSshTransport? _transport;

    /// <summary>
    /// Gets the socket carrying the SSH session, or <see langword="null"/> before a connection has
    /// been established.
    /// </summary>
    public StreamSocket? Socket => _transport?.Socket;

    /// <inheritdoc/>
    public SshTransport Connect(string host, int port, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        return ConnectAsync(host, port, cts.Token).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public async Task<SshTransport> ConnectAsync(string host, int port, CancellationToken cancellationToken)
    {
        var transport = await StreamSocketSshTransport.ConnectAsync(host, port, cancellationToken)
                                                      .ConfigureAwait(false);
        _transport = transport;
        return transport;
    }
}
