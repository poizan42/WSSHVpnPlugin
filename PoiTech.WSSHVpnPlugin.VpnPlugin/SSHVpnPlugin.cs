using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Vpn;
using Windows.System;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// A VPN plug-in that carries traffic over an SSH connection.
/// </summary>
/// <remarks>
/// <para>
/// SSH cannot carry raw IP datagrams: its forwarding primitive (<c>direct-tcpip</c>) is a byte
/// stream to a named host and port. So unlike a conventional plug-in, this one does not
/// "encapsulate" packets one for one. Instead it terminates the tunnelled traffic locally —
/// a user-space TCP/IP stack consumes the IP packets the platform hands to
/// <see cref="Encapsulate"/>, opens one SSH channel per TCP flow, and synthesises the IP
/// packets for the return direction.
/// </para>
/// <para>
/// The instance is long-lived: the background task host creates it once and reuses it for every
/// event on the channel. See <see cref="VpnBackgroundTask"/>.
/// </para>
/// </remarks>
public sealed class SSHVpnPlugin : IVpnPlugIn
{
    /// <summary>
    /// How long to wait between reporting outbound packet failures. <see cref="Encapsulate"/> runs
    /// at line rate, so an unconditional log there fills the disk on any systematic failure.
    /// </summary>
    private const long FailureReportIntervalMs = 10_000;

    private readonly object _stateGate = new();
    private SshVpnConnection? _connection;

    private M0Spike? _spike;

    private long _encapsulateFailureCount;
    private long _lastFailureReportTicks;
    private Exception? _lastEncapsulateFailure;

    /// <inheritdoc/>
    public void Connect(VpnChannel channel)
    {
        ArgumentNullException.ThrowIfNull(channel);

        try
        {
            var configuration = SshVpnConfiguration.FromChannelConfiguration(channel.Configuration);
            PluginLog.Info($"Connecting to {configuration.Host}:{configuration.Port}");

            // A key-based profile that already names its user needs nothing from the user, and
            // asking anyway would put a prompt in front of a background task for no reason.
            var needsCredentials = configuration.PrivateKeyPath is null || configuration.UserName is null;

            var credential = needsCredentials
                ? channel.RequestCredentials(
                    VpnCredentialType.UsernamePassword,
                    isRetry: false,
                    isSingleSignOnCredential: false,
                    certificate: null)
                : null;

            var userName = configuration.UserName ?? credential?.PasskeyCredential?.UserName;
            if (string.IsNullOrEmpty(userName))
            {
                throw new InvalidOperationException("No SSH user name was configured or supplied.");
            }

            // SSH runs on a socket of its own, which is never handed to the platform. See the
            // transport section of CLAUDE.md: the platform takes exclusive ownership of whatever is
            // passed to AssociateTransport and reads it itself, so a session running over it has
            // its bytes consumed — we watched the SSH banner come back corrupted.
            var connection = SshVpnConnection.Establish(
                configuration,
                userName,
                credential?.PasskeyCredential?.Password ?? string.Empty);

            lock (_stateGate)
            {
                _connection?.Dispose();
                _connection = connection;
            }

            // Starting the tunnel needs the outer transport reworked first: the platform must be
            // given a loopback dummy socket to own, while this SSH socket stays bound to the
            // physical interface and out of the tunnel. Until that exists there is nothing sound to
            // pass to Start, and every ordering of AssociateTransport and Start* has been shown to
            // fail. Deliberately explicit rather than half-working.
            //
            // Once it starts, this is where the channel starts and, when configured, the M0 spike
            // runs: M0Spike.Start(channel, connection, configuration.ClientIPv4).
            throw new NotSupportedException(
                "The outer tunnel transport has not been reworked yet; see the transport section of CLAUDE.md.");
        }
        catch (Exception ex)
        {
            PluginLog.Error("Connect failed", ex);
            CloseConnection();

            // TerminateConnection, not SetErrorMessage: the latter is documented as not supported.
            channel.TerminateConnection(ex.Message);
        }
    }

    /// <summary>
    /// Starts the channel, trying each candidate argument shape until one is accepted.
    /// </summary>
    /// <remarks>
    /// Exactly one attempt: the channel is single-shot, and a second call after a rejected one
    /// returns <c>E_ILLEGAL_METHOD_CALL</c> rather than being retried on its merits.
    /// </remarks>
    private static void StartChannel(VpnChannel channel, SshVpnConfiguration configuration)
    {
        // A stable identifier for the virtual interface; a fixed locally-administered
        // MAC-shaped value serves.
        var interfaceId = new VpnInterfaceId(new byte[] { 0x02, 0x57, 0x53, 0x53, 0x48, 0x01 });

        try
        {
            channel.StartExistingTransports(
                new List<HostName> { new HostName(configuration.ClientIPv4) }, // assigned IPv4
                new List<HostName>(),                                          // assigned IPv6
                interfaceId,
                BuildRouteAssignment(configuration),
                BuildDomainNameAssignment(configuration),
                configuration.Mtu,
                GetMaxFrameSize(configuration.Mtu),
                false);                                                        // reserved

            PluginLog.Info("StartExistingTransports accepted");
        }
        catch (Exception ex)
        {
            PluginLog.Error($"StartExistingTransports rejected: 0x{ex.HResult:X8}", ex);
            throw;
        }
    }

    /// <summary>
    /// Gets the frame size to advertise for the given MTU.
    /// </summary>
    /// <remarks>
    /// The platform sizes the send buffer pool from this and documents a hard ceiling of 1500,
    /// reducing either the MTU or the encapsulation overhead if the sum would exceed it. We add no
    /// encapsulation of our own — the SSH session owns the wire — so the MTU alone would do; the
    /// clamp exists so that a profile configuring a larger MTU degrades rather than being rejected.
    /// </remarks>
    private static uint GetMaxFrameSize(uint mtu)
    {
        const uint PlatformMaxFrameSize = 1500;
        const uint HeaderRoom = 128;

        return Math.Min(mtu + HeaderRoom, PlatformMaxFrameSize);
    }

    /// <summary>
    /// Reports outbound packet failures, at most once per <see cref="FailureReportIntervalMs"/>.
    /// </summary>
    /// <param name="failures">The number of failures in the batch just processed.</param>
    private void ReportEncapsulateFailures(int failures)
    {
        var total = Interlocked.Add(ref _encapsulateFailureCount, failures);

        var now = Environment.TickCount64;
        var previous = Interlocked.Read(ref _lastFailureReportTicks);
        if (now - previous < FailureReportIntervalMs)
        {
            return;
        }

        // Losing the race just means another thread reports instead.
        if (Interlocked.CompareExchange(ref _lastFailureReportTicks, now, previous) != previous)
        {
            return;
        }

        PluginLog.Error(
            string.Format(CultureInfo.InvariantCulture, "{0} outbound packet(s) failed so far", total),
            _lastEncapsulateFailure);
    }

    /// <inheritdoc/>
    public void Disconnect(VpnChannel channel)
    {
        ArgumentNullException.ThrowIfNull(channel);

        PluginLog.Info("Disconnecting");
        try
        {
            CloseConnection();
            channel.Stop();
        }
        catch (Exception ex)
        {
            PluginLog.Error("Disconnect failed", ex);
        }
    }

    /// <summary>
    /// Consumes IP packets destined for the tunnel.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Nothing is added to <paramref name="encapsulatedPackets"/>: the platform's send path is
    /// only used when the plug-in wraps packets for a transport the platform owns. Here the SSH
    /// session owns the wire, so the packets are handed to the user-space stack and this method
    /// returns an empty list.
    /// </para>
    /// <para>
    /// The buffers are <em>enumerated</em> rather than removed. Every buffer the platform hands us
    /// has to be given back, and the only documented return paths are this method's out-list and
    /// <see cref="Decapsulate"/>'s; a buffer pulled off the list and dropped is leaked, and the
    /// documented consequence is that the plug-in stops being able to request buffers at all.
    /// Leaving them in <paramref name="packets"/> lets the framework reclaim them.
    /// </para>
    /// </remarks>
    public void Encapsulate(VpnChannel channel, VpnPacketBufferList packets, VpnPacketBufferList encapsulatedPackets)
    {
        ArgumentNullException.ThrowIfNull(packets);

        var connection = GetConnection();
        if (connection is null)
        {
            return;
        }

        var spike = GetSpike();
        var failures = 0;

        foreach (var buffer in packets)
        {
            try
            {
                spike?.SampleOutbound(VpnPacketBufferAccess.GetSpan(buffer).Slice(0, checked((int)buffer.Buffer.Length)));

                // TODO: hand the IP packet to the user-space TCP/IP stack, which maps each TCP
                // flow onto an SSH direct-tcpip channel.
                connection.SendOutbound(buffer);
            }
            catch (Exception ex)
            {
                // Deliberately not logged per packet: a systematic failure here runs at line rate
                // and would fill the disk. Count them and log once for the batch instead.
                failures++;
                _lastEncapsulateFailure = ex;
            }
        }

        if (failures > 0)
        {
            ReportEncapsulateFailures(failures);
        }
    }

    /// <summary>
    /// Turns bytes received on a platform-owned transport back into IP packets.
    /// </summary>
    /// <remarks>
    /// Unused for now. The platform only raises this event for transports it reads on the
    /// plug-in's behalf; inbound traffic here is produced by the user-space stack and injected
    /// with <see cref="VpnChannel.RequestVpnPacketBuffer"/> /
    /// <see cref="VpnChannel.AppendVpnReceivePacketBuffer"/> from the SSH receive loop instead.
    /// </remarks>
    public void Decapsulate(
        VpnChannel channel,
        VpnPacketBuffer encapBuffer,
        VpnPacketBufferList decapsulatedPackets,
        VpnPacketBufferList controlPacketsToSend)
    {
        // Intentionally empty; see the remarks above.
    }

    /// <summary>
    /// Supplies a keep-alive payload for the platform to send on an idle tunnel.
    /// </summary>
    /// <remarks>
    /// SSH runs its own keep-alive (<see cref="Renci.SshNet.BaseClient.KeepAliveInterval"/>), so
    /// no platform-level keep-alive packet is produced.
    /// </remarks>
    public void GetKeepAlivePayload(VpnChannel channel, out VpnPacketBuffer keepAlivePacket)
    {
        keepAlivePacket = null!;
    }

    private SshVpnConnection? GetConnection()
    {
        lock (_stateGate)
        {
            return _connection;
        }
    }

    private M0Spike? GetSpike()
    {
        lock (_stateGate)
        {
            return _spike;
        }
    }

    private void CloseConnection()
    {
        SshVpnConnection? connection;
        M0Spike? spike;

        lock (_stateGate)
        {
            connection = _connection;
            _connection = null;
            spike = _spike;
            _spike = null;
        }

        // The spike probes the connection, so stop it before disposing what it probes.
        spike?.Dispose();
        connection?.Dispose();
    }

    private static VpnRouteAssignment BuildRouteAssignment(SshVpnConfiguration configuration)
    {
        var assignment = new VpnRouteAssignment { ExcludeLocalSubnets = true };

        if (configuration.InclusionRoutes.Count == 0)
        {
            // Default route: everything except the local subnets goes through the tunnel.
            assignment.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("0.0.0.0"), 0));
        }
        else
        {
            foreach (var route in configuration.InclusionRoutes)
            {
                assignment.Ipv4InclusionRoutes.Add(ParseRoute(route));
            }
        }

        return assignment;
    }

    private static VpnDomainNameAssignment BuildDomainNameAssignment(SshVpnConfiguration configuration)
    {
        var assignment = new VpnDomainNameAssignment();
        if (configuration.DnsServers.Count == 0)
        {
            return assignment;
        }

        var dnsServers = new List<HostName>(configuration.DnsServers.Count);
        foreach (var server in configuration.DnsServers)
        {
            dnsServers.Add(new HostName(server));
        }

        // "." is the catch-all suffix: resolve every name through these servers.
        assignment.DomainNameList.Add(
            new VpnDomainNameInfo(".", VpnDomainNameType.Suffix, dnsServers, new List<HostName>()));

        return assignment;
    }

    private static VpnRoute ParseRoute(string cidr)
    {
        var slash = cidr.IndexOf('/');
        if (slash < 0)
        {
            return new VpnRoute(new HostName(cidr), 32);
        }

        var address = cidr[..slash];
        if (!byte.TryParse(cidr[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix))
        {
            throw new FormatException($"'{cidr}' is not a valid route: the prefix length is not a number.");
        }

        return new VpnRoute(new HostName(address), prefix);
    }
}
