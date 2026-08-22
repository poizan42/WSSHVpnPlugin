using System;
using System.IO;
using System.Threading;
using Renci.SshNet;
using Renci.SshNet.Common;
using Renci.SshNet.Connection;
using Windows.Networking;
using Windows.Networking.Vpn;
using Windows.Storage;
using Windows.Storage.AccessCache;
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

    /// <summary>
    /// Connects and authenticates through a transport the caller already built — the
    /// platform-owned-transport path, where the wire is the VPN channel itself.
    /// </summary>
    /// <remarks>
    /// No socket, no interface selection, no classic/WinRT fallback: the platform owns the TCP
    /// connection, the channel is already started, and the handshake's bytes ride decapsulate
    /// deliveries in and the send-buffer lane out.
    /// </remarks>
    public static SshVpnConnection EstablishOverChannel(
        SshVpnConfiguration configuration,
        string userName,
        string password,
        ISshTransportFactory transportFactory)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(transportFactory);

        var authentication = CreateAuthenticationMethod(configuration, userName, password);

        return Establish(configuration, userName, authentication, transportFactory, "platform-owned channel");
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

            // Logged because the suite decides a real share of the host's CPU and cannot be inferred
            // from anything else in this log. A separate MAC algorithm means a separate hashing pass
            // over every packet, which measured 12% of process CPU on a machine whose AES is hardware
            // and whose SHA-256 is not; an AEAD cipher reports no MAC because it needs none. We offer
            // AEAD ahead of CTR, so a MAC appearing here means the server offered no AEAD suite.
            var info = client.ConnectionInfo;
            PluginLog.Info(
                $"Negotiated: kex {info.CurrentKeyExchangeAlgorithm}, host key {info.CurrentHostKeyAlgorithm}, "
                + $"cipher in {info.CurrentServerEncryption} out {info.CurrentClientEncryption}, "
                + $"mac in {info.CurrentServerHmacAlgorithm ?? "none (AEAD)"} "
                + $"out {info.CurrentClientHmacAlgorithm ?? "none (AEAD)"}");

            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Chooses how to authenticate: the private key the app picked, otherwise a password.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Encrypted keys are not supported: a background task has nowhere to prompt for a passphrase,
    /// which is the same reason host keys must be pinned.
    /// </para>
    /// <para>
    /// The key is read through <see cref="StorageFile"/> rather than <c>System.IO.File</c>, and that
    /// is load-bearing. The plug-in runs in an app container, and a raw Win32 open is checked against
    /// the file's ACL, which for an ordinary user file carries no <c>ALL APPLICATION PACKAGES</c>
    /// entry - so <c>File.OpenRead</c> fails with <c>UnauthorizedAccessException</c> however the
    /// access was granted. Only the <c>Windows.Storage</c> broker honours it.
    /// </para>
    /// </remarks>
    private static AuthenticationMethod CreateAuthenticationMethod(
        SshVpnConfiguration configuration,
        string userName,
        string password)
    {
        if (configuration.PrivateKeyToken is not { Length: > 0 } token)
        {
            return new PasswordAuthenticationMethod(userName, password);
        }

        try
        {
            using var keyStream = new MemoryStream(ReadThroughToken(token), writable: false);
            var privateKey = new PrivateKeyFile(keyStream);
            return new PrivateKeyAuthenticationMethod(userName, privateKey);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            throw new InvalidOperationException(
                "The private key could not be read. Choose the key file again in the app: the token " +
                "in the profile is what grants this plug-in access to it, and package state does not " +
                "necessarily survive a reinstall.",
                ex);
        }
    }

    /// <summary>
    /// Reads the private key through the FutureAccessList entry the app created for it.
    /// </summary>
    /// <remarks>
    /// The entry count is logged because it separates a stale token from a list this process cannot
    /// see at all - the app adds the entry, and this runs in the background-task host, a separate
    /// process with its own Application Id under the same package identity.
    /// </remarks>
    private static byte[] ReadThroughToken(string token)
    {
        var list = StorageApplicationPermissions.FutureAccessList;
        PluginLog.Info(
            $"FutureAccessList as seen by the plug-in host: {list.Entries.Count} entry(ies); "
            + $"redeeming '{token}'");

        var file = list.GetFileAsync(token).AsTask().GetAwaiter().GetResult();
        var buffer = FileIO.ReadBufferAsync(file).AsTask().GetAwaiter().GetResult();

        var bytes = new byte[buffer.Length];
        DataReader.FromBuffer(buffer).ReadBytes(bytes);

        PluginLog.Info($"Token redeemed: {file.Path} ({bytes.Length} bytes)");
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
