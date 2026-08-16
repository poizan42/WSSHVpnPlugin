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
    private readonly TimeSpan _openTimeout;
    private PacketPath? _packetPath;
    private int _disposed;

    private SshVpnConnection(SshClient client, string? expectedFingerprint, TimeSpan openTimeout)
    {
        _client = client;
        _expectedFingerprint = expectedFingerprint;
        _openTimeout = openTimeout;
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

        // A classic socket first, the WinRT socket only as the fallback. The WinRT transport was
        // written on the belief that classic sockets are unusable in an app container - which dates
        // from .NET Native and needed retesting on modern .NET. The order matters for speed: a
        // session over a StreamSocket plateaued at the throughput of an unscaled 64 KB TCP window
        // (~10 Mbit/s at a 48 ms round trip), while classic Winsock gets window scaling and receive
        // auto-tuning. Which transport actually carried the session is in the log either way.
        var authentication = CreateAuthenticationMethod(configuration, userName, password);

        try
        {
            var boundAddress = localAddress is null ? null : System.Net.IPAddress.Parse(localAddress.CanonicalName);

            return Establish(
                configuration,
                userName,
                authentication,
                new BoundSocketSshTransportFactory(boundAddress),
                "classic socket");
        }
        catch (Exception ex) when (ex is System.Net.Sockets.SocketException or UnauthorizedAccessException)
        {
            PluginLog.Error("Classic socket refused; falling back to the WinRT socket", ex);

            return Establish(
                configuration,
                userName,
                authentication,
                new StreamSocketSshTransportFactory(localAddress),
                "WinRT StreamSocket");
        }
    }

    private static SshVpnConnection Establish(
        SshVpnConfiguration configuration,
        string userName,
        AuthenticationMethod authentication,
        ISshTransportFactory transportFactory,
        string transportName)
    {
        var connectionInfo = new ConnectionInfo(
            configuration.Host,
            checked((int)configuration.Port),
            userName,
            authentication)
        {
            TransportFactory = transportFactory,

            // Send the close and move on, rather than waiting a second for the server to answer it.
            // Closing runs on the stack's thread, which owns every flow and must never block: at the
            // rate an idle machine opens and closes channels, waiting even one round trip there
            // stalls every other flow. Nothing needs the acknowledgement — channel numbers are never
            // reused (Session.NextChannelNumber only ever increments), so a late CHANNEL_CLOSE
            // arrives for a number nobody answers to and is discarded.
            ChannelCloseTimeout = TimeSpan.Zero,
        };

        var client = new SshClient(connectionInfo);
        var connection = new SshVpnConnection(
            client,
            NormalizeFingerprint(configuration.HostKeyFingerprint),
            TimeSpan.FromSeconds(configuration.OpenTimeoutSeconds));
        try
        {
            client.HostKeyReceived += connection.OnHostKeyReceived;
            client.KeepAliveInterval = KeepAliveInterval;
            client.Connect();
            PluginLog.Info($"SSH session established with {configuration.Host}:{configuration.Port} over {transportName}");
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
    /// Gives the connection the platform-side plumbing the packet path needs, once the channel has
    /// started.
    /// </summary>
    /// <param name="inbound">The queue that carries packets back to the platform.</param>
    /// <param name="transport">The transport whose doorbell provokes a decapsulate call.</param>
    /// <remarks>
    /// Separate from <see cref="Establish"/> because the SSH session is established before the
    /// channel starts, and neither of these exists until it has.
    /// </remarks>
    public void AttachPacketPath(InboundPacketQueue inbound, IOuterTransport transport)
    {
        ArgumentNullException.ThrowIfNull(inbound);
        ArgumentNullException.ThrowIfNull(transport);

        var path = new PacketPath(_client, inbound, transport, _openTimeout);
        _packetPath = path;
        path.Start();

        PluginLog.Info("Packet path started; every TCP flow gets its own channel.");
    }

    /// <summary>
    /// Accepts an IP packet the platform wants sent through the tunnel.
    /// </summary>
    /// <remarks>
    /// Hands it to the stack's thread and returns. Every TCP flow gets its own <c>direct-tcpip</c>
    /// channel; anything else — UDP, ICMP, broadcast, multicast — is dropped by the stack, since
    /// plain SSH has no forwarding primitive for any of it. DNS is the gap that matters, and it is
    /// answered by carrying it over TCP instead. Takes the bytes rather than the platform's buffer
    /// object: the caller owns the buffer's rotation, and this class has no per-packet WinRT
    /// dependency at all.
    /// </remarks>
    public void SendOutbound(ReadOnlySpan<byte> packet)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        _packetPath?.Offer(packet);
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
            _packetPath?.Dispose();
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
