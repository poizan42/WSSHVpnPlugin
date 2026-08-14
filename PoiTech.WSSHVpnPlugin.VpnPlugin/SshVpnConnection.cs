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
    private readonly string? _expectedFingerprint;
    private int _disposed;

    private SshVpnConnection(SshClient client, string? expectedFingerprint)
    {
        _client = client;
        _expectedFingerprint = expectedFingerprint;
    }

    /// <summary>
    /// Gets the object the platform should treat as the outer tunnel transport, so that the SSH
    /// connection's own traffic is not routed back into the tunnel it carries.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="VpnChannel.Start"/> expects a <c>Windows.Networking.Sockets.StreamSocket</c> or
    /// <c>DatagramSocket</c>. SSH.NET connects with a <c>System.Net.Sockets.Socket</c>, which the
    /// platform will not accept, so there is nothing to hand over yet.
    /// </para>
    /// <para>
    /// The two ways out are (a) teach the SSH.NET fork to run its transport over a WinRT
    /// <c>StreamSocket</c>, or (b) skip the association and instead keep the server out of the
    /// tunnel with an explicit exclusion route for its address. (a) is more faithful to what the
    /// platform expects — it also drives reconnect-on-transport-change — but is the larger change.
    /// </para>
    /// </remarks>
    public object? OuterTunnelTransport =>
        throw new NotImplementedException(
            "The SSH transport is not yet exposed as a WinRT socket; see SshVpnConnection.OuterTunnelTransport.");

    /// <summary>
    /// Connects and authenticates to the SSH server described by <paramref name="configuration"/>.
    /// </summary>
    public static SshVpnConnection Establish(SshVpnConfiguration configuration, string userName, string password)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        // TODO: support public key authentication (PrivateKeyAuthenticationMethod) in addition to
        // passwords, and keyboard-interactive for servers that require it.
        var connectionInfo = new ConnectionInfo(
            configuration.Host,
            checked((int)configuration.Port),
            userName,
            new PasswordAuthenticationMethod(userName, password));

        var client = new SshClient(connectionInfo);
        var connection = new SshVpnConnection(client, NormalizeFingerprint(configuration.HostKeyFingerprint));
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
