using System;
using System.Collections.Generic;
using System.Globalization;
using System.Xml.Linq;
using Windows.Networking;
using Windows.Networking.Vpn;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// The plug-in's view of the VPN profile.
/// </summary>
/// <remarks>
/// <para>
/// The host to connect to comes from the profile's server URI list, which the platform surfaces
/// as <see cref="VpnChannelConfiguration.ServerHostNameList"/>. Everything else is carried in
/// the profile's custom configuration string, which is opaque to the platform. The expected
/// shape is:
/// </para>
/// <code>
/// &lt;SshVpnConfiguration&gt;
///   &lt;Port&gt;22&lt;/Port&gt;
///   &lt;UserName&gt;alice&lt;/UserName&gt;
///   &lt;HostKeyFingerprint&gt;SHA256:xxxxxxxx&lt;/HostKeyFingerprint&gt;
///   &lt;ClientIPv4&gt;192.168.255.2&lt;/ClientIPv4&gt;
///   &lt;NetworkAdapter&gt;192.168.1.20&lt;/NetworkAdapter&gt;
///   &lt;Mtu&gt;1400&lt;/Mtu&gt;
///   &lt;DnsServer&gt;1.1.1.1&lt;/DnsServer&gt;
///   &lt;InclusionRoute&gt;10.0.0.0/8&lt;/InclusionRoute&gt;
/// &lt;/SshVpnConfiguration&gt;
/// </code>
/// </remarks>
internal sealed class SshVpnConfiguration
{
    public const string RootElementName = "SshVpnConfiguration";

    private SshVpnConfiguration(string host)
    {
        Host = host;
    }

    /// <summary>Gets the SSH server host name or address.</summary>
    public string Host { get; }

    /// <summary>Gets the SSH server port.</summary>
    public uint Port { get; private init; } = 22;

    /// <summary>Gets the SSH user name, or <see langword="null"/> to prompt the user.</summary>
    public string? UserName { get; private init; }

    /// <summary>
    /// Gets the path of an unencrypted private key to authenticate with, or <see langword="null"/>
    /// to authenticate with a password.
    /// </summary>
    public string? PrivateKeyPath { get; private init; }

    /// <summary>
    /// Gets how long to wait before starting the channel, so a debugger can be attached to the
    /// background task host first.
    /// </summary>
    /// <remarks>
    /// The host is created per activation and exits when the connect fails, and the whole sequence
    /// takes about a second — far too little to attach by hand. Waiting here is the difference
    /// between racing the process and simply catching it.
    /// </remarks>
    public uint StartDelaySeconds { get; private init; }

    /// <summary>
    /// Gets the expected server host key fingerprint. When set, the host key is pinned to this
    /// value; when unset, the connection is refused rather than trusted blindly.
    /// </summary>
    public string? HostKeyFingerprint { get; private init; }

    /// <summary>Gets the IPv4 address to assign to the virtual interface.</summary>
    public string ClientIPv4 { get; private init; } = "192.168.255.2";

    /// <summary>
    /// Gets the interface the SSH session should connect from — either an IPv4 literal or the name
    /// of a network connection — or <see langword="null"/> to choose one automatically.
    /// </summary>
    /// <remarks>
    /// Needed whenever the automatic choice cannot be trusted, and it cannot be trusted when this
    /// tunnel runs nested inside another VPN: an adapter belonging to another VPN is
    /// indistinguishable from a physical one, so SSH would be bound underneath it and leave that
    /// VPN. See <see cref="OutboundInterface"/>.
    /// </remarks>
    public string? NetworkAdapter { get; private init; }

    /// <summary>
    /// Gets how many seconds a channel open may wait for the server's answer before the connection
    /// it carries is refused.
    /// </summary>
    /// <remarks>
    /// Bounds the caller's wait, not the channel's life: a timed-out open is abandoned, and the
    /// abandoned object holds its slot until the server answers. The default must stay below the
    /// DNS relay's 5-second query deadline, or an open outlives the query that wanted it whenever a
    /// DNS server channel has to be re-established.
    /// </remarks>
    public uint OpenTimeoutSeconds { get; private init; } = 3;

    /// <summary>Gets the DNS servers to assign, if any.</summary>
    public IReadOnlyList<string> DnsServers { get; private init; } = Array.Empty<string>();

    /// <summary>
    /// Gets the IPv4 routes to direct into the tunnel, in CIDR form. An empty list means
    /// "default route": send everything through the tunnel.
    /// </summary>
    public IReadOnlyList<string> InclusionRoutes { get; private init; } = Array.Empty<string>();

    /// <summary>
    /// Gets the IPv4 routes to keep out of the tunnel, in CIDR form.
    /// </summary>
    /// <remarks>
    /// Explicit rather than a blanket rule about private addresses, because the same machinery
    /// carries the opposite case: reaching the network on the far side is the point of a VPN, and its
    /// addresses are private too. What belongs here is the client's own subnets - the printer, the
    /// domain controller, the machine next to it - which the far side cannot reach and should not be
    /// asked to.
    /// </remarks>
    public IReadOnlyList<string> ExclusionRoutes { get; private init; } = Array.Empty<string>();

    /// <summary>
    /// Reads the configuration carried by the VPN profile.
    /// </summary>
    /// <exception cref="FormatException">The profile is missing a server, or the custom configuration is malformed.</exception>
    public static SshVpnConfiguration FromChannelConfiguration(VpnChannelConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var custom = configuration.CustomField;
        if (string.IsNullOrWhiteSpace(custom))
        {
            throw new FormatException("The VPN profile carries no custom configuration.");
        }

        XElement root;
        try
        {
            root = XDocument.Parse(custom).Root
                ?? throw new FormatException("The custom configuration is empty.");
        }
        catch (System.Xml.XmlException ex)
        {
            throw new FormatException("The custom configuration is not well-formed XML.", ex);
        }

        if (root.Name.LocalName != RootElementName)
        {
            throw new FormatException(
                $"Expected a <{RootElementName}> root element but found <{root.Name.LocalName}>.");
        }

        var host = ReadString(root, "Host")
            ?? TryGetFirstServerHost(configuration)
            ?? throw new FormatException("The VPN profile does not specify a server host name.");

        return new SshVpnConfiguration(host)
        {
            Port = ReadUInt32(root, "Port", 22),
            UserName = ReadString(root, "UserName"),
            PrivateKeyPath = ReadString(root, "PrivateKeyPath"),
            StartDelaySeconds = ReadUInt32(root, "StartDelaySeconds", 0),
            HostKeyFingerprint = ReadString(root, "HostKeyFingerprint"),
            ClientIPv4 = ReadString(root, "ClientIPv4") ?? "192.168.255.2",
            NetworkAdapter = ReadString(root, "NetworkAdapter"),
            OpenTimeoutSeconds = ReadUInt32(root, "OpenTimeoutSeconds", 3),
            DnsServers = ReadStringList(root, "DnsServer"),
            InclusionRoutes = ReadStringList(root, "InclusionRoute"),
            ExclusionRoutes = ReadStringList(root, "ExcludeRoute"),
        };
    }

    /// <summary>
    /// Reads the host from the platform's server list, if it will give us one.
    /// </summary>
    /// <remarks>
    /// Observed: for a plug-in profile whose <c>ServerUris</c> were set, merely reading
    /// <see cref="VpnChannelConfiguration.ServerHostNameList"/> throws
    /// <c>ArgumentException("hostName")</c> from the projection — with both an <c>ssh://</c> and an
    /// <c>https://</c> URI, so it is not about the scheme. The host is therefore carried in the
    /// custom configuration, which we control end to end, and this is only a fallback so that a
    /// profile provisioned by other means (MDM, say) still works.
    /// </remarks>
    private static string? TryGetFirstServerHost(VpnChannelConfiguration configuration)
    {
        try
        {
            return GetFirstServerHost(configuration.ServerHostNameList);
        }
        catch (Exception ex)
        {
            PluginLog.Error("The platform would not surface ServerHostNameList; using <Host> instead", ex);
            return null;
        }
    }

    private static string? GetFirstServerHost(IReadOnlyList<HostName>? servers)
    {
        if (servers is null)
        {
            return null;
        }

        foreach (var server in servers)
        {
            var name = server.CanonicalName;
            if (!string.IsNullOrWhiteSpace(name))
            {
                return name;
            }
        }

        return null;
    }

    private static string? ReadString(XElement root, string name)
    {
        var value = root.Element(name)?.Value.Trim();
        return string.IsNullOrEmpty(value) ? null : value;
    }

    private static uint ReadUInt32(XElement root, string name, uint defaultValue)
    {
        var raw = ReadString(root, name);
        if (raw is null)
        {
            return defaultValue;
        }

        if (!uint.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var value))
        {
            throw new FormatException($"<{name}> is not a valid unsigned integer: '{raw}'.");
        }

        return value;
    }

    private static IReadOnlyList<string> ReadStringList(XElement root, string name)
    {
        List<string>? values = null;
        foreach (var element in root.Elements(name))
        {
            var value = element.Value.Trim();
            if (value.Length > 0)
            {
                (values ??= new List<string>()).Add(value);
            }
        }

        return (IReadOnlyList<string>?)values ?? Array.Empty<string>();
    }
}
