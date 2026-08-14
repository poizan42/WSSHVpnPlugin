using System;
using System.Threading;
using Renci.SshNet;
using Renci.SshNet.Common;
using Windows.Networking.Vpn;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Owns the live SSH session that backs a VPN channel.
/// </summary>
internal sealed class SshVpnConnection : IDisposable
{
    private static readonly TimeSpan KeepAliveInterval = TimeSpan.FromSeconds(30);

    private readonly SshClient _client;
    private readonly StreamSocketSshTransportFactory _transportFactory;
    private readonly string? _expectedFingerprint;
    private int _disposed;

    private SshVpnConnection(
        SshClient client,
        StreamSocketSshTransportFactory transportFactory,
        string? expectedFingerprint)
    {
        _client = client;
        _transportFactory = transportFactory;
        _expectedFingerprint = expectedFingerprint;
    }

    /// <summary>
    /// Gets the socket the platform should treat as the outer tunnel transport, so that the SSH
    /// connection's own traffic is not routed back into the tunnel it carries.
    /// </summary>
    /// <remarks>
    /// This is the same <c>StreamSocket</c> the session is running over. The SSH.NET fork was
    /// changed to accept a caller-supplied transport precisely so that this socket exists as a
    /// WinRT object — see <see cref="StreamSocketSshTransport"/>.
    /// </remarks>
    public object OuterTunnelTransport =>
        _transportFactory.Socket
        ?? throw new InvalidOperationException("The SSH session has not been established.");

    /// <summary>
    /// Connects and authenticates to the SSH server described by <paramref name="configuration"/>.
    /// </summary>
    public static SshVpnConnection Establish(SshVpnConfiguration configuration, string userName, string password)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var transportFactory = new StreamSocketSshTransportFactory();

        // TODO: support public key authentication (PrivateKeyAuthenticationMethod) in addition to
        // passwords, and keyboard-interactive for servers that require it.
        var connectionInfo = new ConnectionInfo(
            configuration.Host,
            checked((int)configuration.Port),
            userName,
            new PasswordAuthenticationMethod(userName, password))
        {
            // Run the session over a WinRT StreamSocket rather than System.Net.Sockets.Socket, so
            // the platform can be handed the socket and keep this connection out of the tunnel.
            TransportFactory = transportFactory,
        };

        var client = new SshClient(connectionInfo);
        var connection = new SshVpnConnection(
            client,
            transportFactory,
            NormalizeFingerprint(configuration.HostKeyFingerprint));
        try
        {
            client.HostKeyReceived += connection.OnHostKeyReceived;
            client.KeepAliveInterval = KeepAliveInterval;
            client.Connect();
            PluginLog.Info($"SSH session established with {configuration.Host}:{configuration.Port}");
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Accepts an IP packet the platform wants sent through the tunnel.
    /// </summary>
    /// <remarks>
    /// TODO: this is where the user-space TCP/IP stack goes. It has to demultiplex the packet by
    /// flow, open a <c>direct-tcpip</c> channel for each new TCP connection (which is what the
    /// SSH.NET fork exists to make reachable), and drive the SSH channel's byte stream. UDP and
    /// ICMP need a separate answer — plain SSH has no forwarding primitive for either.
    /// </remarks>
    public void SendOutbound(VpnPacketBuffer packet)
    {
        ArgumentNullException.ThrowIfNull(packet);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
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
            _client.HostKeyReceived -= OnHostKeyReceived;
            _client.Dispose();
        }
        catch (Exception ex)
        {
            PluginLog.Error("Failed to close the SSH session cleanly", ex);
        }
    }

    /// <summary>
    /// Strips the <c>SHA256:</c> prefix and any base64 padding, so that fingerprints copied from
    /// OpenSSH output compare equal to what SSH.NET reports.
    /// </summary>
    private static string? NormalizeFingerprint(string? fingerprint)
    {
        if (string.IsNullOrWhiteSpace(fingerprint))
        {
            return null;
        }

        var value = fingerprint.Trim();
        if (value.StartsWith("SHA256:", StringComparison.OrdinalIgnoreCase))
        {
            value = value["SHA256:".Length..];
        }

        return value.TrimEnd('=');
    }

    private void OnHostKeyReceived(object? sender, HostKeyEventArgs e)
    {
        var actual = e.FingerPrintSHA256.TrimEnd('=');

        if (_expectedFingerprint is null)
        {
            // Refusing is the safe default: a VPN plug-in has no UI to prompt from, and
            // trust-on-first-use would let anyone who can intercept the first connection own the
            // tunnel for good.
            PluginLog.Error(
                $"No host key fingerprint is pinned in the profile; refusing the server key SHA256:{actual}");
            e.CanTrust = false;
            return;
        }

        e.CanTrust = string.Equals(actual, _expectedFingerprint, StringComparison.Ordinal);
        if (!e.CanTrust)
        {
            PluginLog.Error(
                $"Host key mismatch: expected SHA256:{_expectedFingerprint} but the server presented SHA256:{actual}");
        }
    }
}
