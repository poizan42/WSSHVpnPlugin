using System;
using System.IO;
using System.Threading;
using Renci.SshNet;
using Renci.SshNet.Common;
using Renci.SshNet.Connection;
using Windows.Networking;
using Windows.Networking.Vpn;
using Windows.Storage;
using Windows.Storage.Streams;

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
    /// Connects and authenticates to the SSH server described by <paramref name="configuration"/>.
    /// </summary>
    /// <param name="configuration">The profile to connect with.</param>
    /// <param name="userName">The user to authenticate as.</param>
    /// <param name="password">The password, when the profile does not name a private key.</param>
    /// <param name="localAddress">
    /// The local address to connect from, or <see langword="null"/> to let the system choose.
    /// </param>
    /// <remarks>
    /// The session is bound to a chosen local address so that its own packets keep using the
    /// physical interface once the tunnel takes over the default route. Without that, the tunnel
    /// carries the connection that carries the tunnel.
    /// </remarks>
    public static SshVpnConnection Establish(
        SshVpnConfiguration configuration,
        string userName,
        string password,
        HostName? localAddress)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        // TODO: keyboard-interactive, for servers that require it.
        var connectionInfo = new ConnectionInfo(
            configuration.Host,
            checked((int)configuration.Port),
            userName,
            CreateAuthenticationMethod(configuration, userName, password))
        {
            // A WinRT StreamSocket rather than System.Net.Sockets.Socket: the plug-in runs in an app
            // container, where the WinRT socket types are what is available.
            TransportFactory = new StreamSocketSshTransportFactory(localAddress),
        };

        var client = new SshClient(connectionInfo);
        var connection = new SshVpnConnection(
            client,
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
    /// Runs a command round trip to prove the SSH session is still usable.
    /// </summary>
    /// <param name="detail">Receives a description of what happened, either way.</param>
    /// <returns>
    /// <see langword="true"/> if the round trip succeeded; otherwise, <see langword="false"/>.
    /// </returns>
    /// <remarks>
    /// A full round trip rather than <c>IsConnected</c> or a keep-alive, both of which would still
    /// look healthy if something else were consuming our inbound bytes. Called only from the M0
    /// spike thread — never from the session's own message loop.
    /// </remarks>
    public bool TryProbe(out string detail)
    {
        try
        {
            using var command = _client.CreateCommand("echo wsshvpn-probe");
            var result = command.Execute()?.Trim();

            if (string.Equals(result, "wsshvpn-probe", StringComparison.Ordinal))
            {
                detail = "round trip ok";
                return true;
            }

            detail = $"unexpected response '{result}'";
            return false;
        }
        catch (Exception ex)
        {
            detail = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Chooses how to authenticate: a private key when the profile names one, otherwise a password.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Encrypted keys are not supported: a background task has nowhere to prompt for a passphrase,
    /// which is the same reason host keys must be pinned.
    /// </para>
    /// <para>
    /// The key is opened through <see cref="StorageFile"/> rather than <c>System.IO.File</c>, and
    /// that is load-bearing. The plug-in runs in an app container, and <c>broadFileSystemAccess</c>
    /// grants reach outside the package's own folders only via the <c>Windows.Storage</c> broker.
    /// A raw Win32 open goes straight to the file system and is checked against the file's ACL,
    /// which for an ordinary user file carries no <c>ALL APPLICATION PACKAGES</c> entry — so
    /// <c>File.OpenRead</c> fails with <c>UnauthorizedAccessException</c> even with the capability
    /// declared and the privacy toggle switched on.
    /// </para>
    /// </remarks>
    private static AuthenticationMethod CreateAuthenticationMethod(
        SshVpnConfiguration configuration,
        string userName,
        string password)
    {
        if (configuration.PrivateKeyPath is not { } keyPath)
        {
            return new PasswordAuthenticationMethod(userName, password);
        }

        PluginLog.Info($"Authenticating with the private key at {keyPath}");

        try
        {
            using var keyStream = new MemoryStream(ReadThroughBroker(keyPath), writable: false);
            var privateKey = new PrivateKeyFile(keyStream);
            return new PrivateKeyAuthenticationMethod(userName, privateKey);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                $"The private key at '{keyPath}' could not be read. Check that the package has the " +
                "broadFileSystemAccess capability and that file system access is enabled for it in " +
                "Settings > Privacy & security > File system.",
                ex);
        }
    }

    /// <summary>
    /// Reads a file through the storage broker, which is what makes
    /// <c>broadFileSystemAccess</c> apply.
    /// </summary>
    private static byte[] ReadThroughBroker(string path)
    {
        var file = StorageFile.GetFileFromPathAsync(path).AsTask().GetAwaiter().GetResult();
        var buffer = FileIO.ReadBufferAsync(file).AsTask().GetAwaiter().GetResult();

        var bytes = new byte[buffer.Length];
        DataReader.FromBuffer(buffer).ReadBytes(bytes);
        return bytes;
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
