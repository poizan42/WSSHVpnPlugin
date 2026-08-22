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
///   &lt;PrivateKeyToken&gt;{GUID from the app's file picker}&lt;/PrivateKeyToken&gt;
///   &lt;ClientIPv4&gt;192.168.255.2&lt;/ClientIPv4&gt;
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
    /// Gets a FutureAccessList token for the unencrypted private key to authenticate with, or
    /// <see langword="null"/> to authenticate with a password.
    /// </summary>
    /// <remarks>
    /// A token, not a path: the app picks the file, and the token is what grants the plug-in access
    /// to it, so the package needs no file-system capability. The list is package-scoped, which is
    /// why the background-task host can redeem what the app added.
    /// </remarks>
    public string? PrivateKeyToken { get; private init; }

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

    /// <summary>The default MTU. The documented maximum for this argument.</summary>
    public const uint DefaultMtu = 1400;

    /// <summary>
    /// Gets the MTU to advertise on the virtual interface, which is also the size of every buffer
    /// in the platform's receive pool.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Configurable because the documented limit and the measured behaviour disagree, and which
    /// Windows builds enforce the limit is unknown. StartWithMainTransport's page says mtuSize
    /// "should be configured to be at most 1400" and that it "is also the size of the
    /// IVpnPacketBuffers in the Receive pool" - and the neighbouring maxFrameSize cap of 1500 is
    /// written for a plug-in that puts one IP packet in one datagram, which is not this
    /// architecture (we already run a 65536 frame size for that reason).
    /// </para>
    /// <para>
    /// 1400, 32768 and 65535 are all accepted on builds 20348 and 26200, so the whole UINT16 range
    /// appears usable - but raising it is not established to help. 32768 measured 222 Mbit/s against
    /// 194 at 1400 on one machine, which is inside that laptop's plus or minus 8 percent run-to-run
    /// spread, and a five-point sweep elsewhere found 1400 through 32768 indistinguishable. Any gain
    /// is per-packet amortisation of the kernel networking path, so it only pays where that path is
    /// the bottleneck.
    /// </para>
    /// <para>
    /// Larger is not better, though, and the receive pool is why - exactly as the documented
    /// sentence above implies, since this value sizes every buffer in it. The pool's budget measures
    /// as a few megabytes and is denominated in bytes rather than buffers: it refuses at around 110
    /// outstanding 32 KiB buffers and around 55 outstanding 64 KiB ones, both about 3.5 MB. So
    /// doubling this halves the packets in flight, and 65535 is worse than 32768 on every count -
    /// 188 Mbit/s peak, and 24,467 refusals in roughly a minute against 11 for a comparable stretch
    /// at 32768. Of those, 3,329 arrived while holding no buffers at all, which is the pool being
    /// empty because the platform has not recycled what it already took, not anything we are
    /// renting. Refusals are absorbed as backpressure - zero drops, zero retransmissions, zero
    /// window-full at either size - so they cost throughput only in that volume.
    /// </para>
    /// <para>
    /// The default stays at the documented value because a rejected value is not survivable: a
    /// refused Start returns E_OUTOFMEMORY, the channel is single-shot afterwards, so there is no
    /// falling back within the activation and the tunnel simply never connects. Raise it per
    /// profile on a build where it has been tried.
    /// </para>
    /// </remarks>
    public uint Mtu { get; private init; } = DefaultMtu;

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
            PrivateKeyToken = ReadString(root, "PrivateKeyToken"),
            StartDelaySeconds = ReadUInt32(root, "StartDelaySeconds", 0),
            HostKeyFingerprint = ReadString(root, "HostKeyFingerprint"),
            ClientIPv4 = ReadString(root, "ClientIPv4") ?? "192.168.255.2",
            OpenTimeoutSeconds = ReadUInt32(root, "OpenTimeoutSeconds", 3),
            Mtu = ReadUInt32(root, "Mtu", DefaultMtu),
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
