using System;
using System.Collections.Generic;
using System.Globalization;
using Windows.Networking;
using Windows.Networking.Vpn;

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
    private readonly object _stateGate = new();
    private SshVpnConnection? _connection;

    /// <inheritdoc/>
    public void Connect(VpnChannel channel)
    {
        ArgumentNullException.ThrowIfNull(channel);

        try
        {
            var configuration = SshVpnConfiguration.FromChannelConfiguration(channel.Configuration);
            PluginLog.Info($"Connecting to {configuration.Host}:{configuration.Port}");

            var credential = channel.RequestCredentials(
                VpnCredentialType.UsernamePassword,
                isRetry: false,
                isSingleSignOnCredential: false,
                certificate: null);
            var userName = configuration.UserName ?? credential.PasskeyCredential?.UserName;
            if (string.IsNullOrEmpty(userName))
            {
                throw new InvalidOperationException("No SSH user name was configured or supplied.");
            }

            var connection = SshVpnConnection.Establish(
                configuration,
                userName,
                credential.PasskeyCredential?.Password ?? string.Empty);

            lock (_stateGate)
            {
                _connection?.Dispose();
                _connection = connection;
            }

            // The StreamSocket the SSH session is running over. Handing it to the platform is what
            // keeps the SSH connection's own traffic out of the tunnel being installed.
            var transport = connection.OuterTunnelTransport;

            // StartWithMainTransport rather than the older Start overload: it takes a
            // VpnDomainNameAssignment (per-namespace DNS) instead of the legacy
            // VpnNamespaceAssignment. StartWithTrafficFilter is the next step up, if per-app or
            // per-port filtering is wanted later.
            channel.StartWithMainTransport(
                new List<HostName> { new HostName(configuration.ClientIPv4) }, // assigned IPv4 addresses
                null,                                                          // assigned IPv6 addresses
                null,                                                          // VpnInterfaceId
                BuildRouteAssignment(configuration),
                BuildDomainNameAssignment(configuration),
                configuration.Mtu,                                             // MTU
                configuration.Mtu + 128,                                       // max frame size
                false,                                                         // reserved
                transport);                                                    // main outer tunnel transport

            PluginLog.Info("Channel started");
        }
        catch (Exception ex)
        {
            PluginLog.Error("Connect failed", ex);
            CloseConnection();
            channel.SetErrorMessage(ex.Message);
        }
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
    /// Nothing is added to <paramref name="encapsulatedPackets"/>: the platform's send path is
    /// only used when the plug-in wraps packets for a transport the platform owns. Here the SSH
    /// session owns the wire, so the packets are handed to the user-space stack and this method
    /// returns an empty list.
    /// </remarks>
    public void Encapsulate(VpnChannel channel, VpnPacketBufferList packets, VpnPacketBufferList encapsulatedPackets)
    {
        ArgumentNullException.ThrowIfNull(packets);

        var connection = GetConnection();
        if (connection is null)
        {
            // Not connected: drop the packets rather than leaking the buffers.
            packets.Clear();
            return;
        }

        while (packets.Size > 0)
        {
            var buffer = packets.RemoveAtBegin();
            try
            {
                // TODO: hand the IP packet to the user-space TCP/IP stack, which maps each TCP
                // flow onto an SSH direct-tcpip channel.
                connection.SendOutbound(buffer);
            }
            catch (Exception ex)
            {
                PluginLog.Error("Failed to process an outbound packet", ex);
            }
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

    private void CloseConnection()
    {
        SshVpnConnection? connection;
        lock (_stateGate)
        {
            connection = _connection;
            _connection = null;
        }

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
