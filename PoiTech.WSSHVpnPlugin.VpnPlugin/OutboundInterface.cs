using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Windows.Networking;
using Windows.Networking.Connectivity;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Chooses the local address the SSH session connects from, so that its own traffic stays on the
/// physical network instead of routing into the tunnel it carries.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="NetworkInformation.GetInternetConnectionProfile"/> is deliberately not used: it is
/// documented to return the <em>preferred</em> interface, which becomes the VPN itself as soon as
/// the tunnel owns the default route. The adapters are enumerated and scored instead.
/// </para>
/// <para>
/// The test is the reference implementation's, unchanged: an adapter qualifies when it is
/// operationally up, has at least one gateway, and has a physical address; Wi-Fi ranks below
/// anything else. That needs <c>GetAdaptersAddresses</c>, because WinRT exposes neither a gateway
/// list nor a physical address — see <see cref="EnumerateViaIpHelper"/>. YtFlowCore's netif plugin
/// makes the same call and is compiled into a shipping UWP VPN plug-in, which is the reason to expect
/// it to work in an app container; it has been checked directly outside one, but whether the
/// container blocks it is answered by the log line the fallback writes.
/// </para>
/// <para>
/// <see cref="EnumerateViaWinRT"/> is that fallback. Its signals are weaker: a connection profile
/// reporting internet connectivity has to stand in for "has a gateway", which wrongly rejects a
/// network with no internet access at all — a LAN-only SSH server, say. Hence a fallback and not the
/// default.
/// </para>
/// <para>
/// What neither can do is tell our own tunnel apart from another VPN's. TAP-style virtual adapters
/// do report a physical address, so one belonging to another VPN qualifies exactly as a physical
/// adapter does and can tie with one; whether a given virtual adapter reports an address at all is
/// up to its driver, so this cannot be relied on either way. Our own interface is excluded only
/// because it is still down when <see cref="Select"/> runs. Running nested under another VPN
/// therefore needs the override, or SSH silently leaves that VPN.
/// </para>
/// </remarks>
internal static unsafe partial class OutboundInterface
{
    /// <summary>IANA <c>ieee80211</c>. The only medium the reference implementation demotes.</summary>
    private const uint IanaWifi = 71;

    /// <summary>
    /// Selects the address to connect from.
    /// </summary>
    /// <param name="preference">
    /// The profile's <c>&lt;NetworkAdapter&gt;</c> override: either an IPv4 literal to use directly,
    /// or an adapter or connection name to match. <see langword="null"/> to choose automatically.
    /// </param>
    /// <returns>
    /// The local address to connect from, or <see langword="null"/> to let the system choose, which
    /// is what happens when nothing suitable is found. Returning <see langword="null"/> rather than
    /// failing is deliberate: an unbound connection still works on a machine with one interface, and
    /// refusing to connect at all would be a worse failure than routing badly.
    /// </returns>
    public static HostName? Select(string? preference)
    {
        if (preference is { Length: > 0 })
        {
            var chosen = SelectExplicitly(preference);
            if (chosen is not null)
            {
                return chosen;
            }

            PluginLog.Error(
                $"The profile asks for network adapter '{preference}', which was not found; choosing automatically.");
        }

        var candidates = Enumerate();
        if (candidates.Count == 0)
        {
            PluginLog.Error(
                "No connected adapter with a gateway was found; SSH will connect from whichever " +
                "address the system picks, which may be the tunnel itself.");
            return null;
        }

        candidates.Sort(static (left, right) => right.Rank.CompareTo(left.Rank));

        foreach (var candidate in candidates)
        {
            PluginLog.Info($"candidate interface: {candidate}");
        }

        var best = candidates[0];
        PluginLog.Info($"SSH will connect from {best.Address} ({best.Name})");
        return new HostName(best.Address);
    }

    /// <summary>
    /// Resolves the profile's override, which names either an address or an adapter.
    /// </summary>
    private static HostName? SelectExplicitly(string preference)
    {
        if (IPAddress.TryParse(preference, out var literal) && literal.AddressFamily == AddressFamily.InterNetwork)
        {
            PluginLog.Info($"SSH will connect from {preference}, as the profile requires");
            return new HostName(preference);
        }

        foreach (var candidate in Enumerate())
        {
            if (string.Equals(candidate.Name, preference, StringComparison.OrdinalIgnoreCase))
            {
                PluginLog.Info($"SSH will connect from {candidate.Address} ('{preference}'), as the profile requires");
                return new HostName(candidate.Address);
            }
        }

        return null;
    }

    /// <summary>
    /// Lists the adapters that could carry the SSH session, preferring the real test to the proxy one.
    /// </summary>
    private static List<Candidate> Enumerate()
    {
        try
        {
            return EnumerateViaIpHelper();
        }
        catch (Exception ex)
        {
            // Worth shouting about: it means the app container blocked a call the reference
            // implementation makes from the same place, and the weaker test is now in charge.
            PluginLog.Error("GetAdaptersAddresses failed; falling back to the WinRT heuristic", ex);
        }

        try
        {
            return EnumerateViaWinRT();
        }
        catch (Exception ex)
        {
            PluginLog.Error("Could not enumerate the network adapters at all", ex);
            return new List<Candidate>();
        }
    }

    /// <summary>
    /// Applies the reference implementation's test: up, with a gateway and a physical address.
    /// </summary>
    private static List<Candidate> EnumerateViaIpHelper()
    {
        const uint AfInet = 2;
        const uint GaaFlagSkipAnycast = 0x0002;
        const uint GaaFlagSkipMulticast = 0x0004;
        const uint GaaFlagSkipDnsServer = 0x0008;
        const uint GaaFlagIncludeGateways = 0x0080;
        const uint ErrorSuccess = 0;
        const uint ErrorBufferOverflow = 111;

        const uint flags = GaaFlagSkipAnycast | GaaFlagSkipMulticast | GaaFlagSkipDnsServer | GaaFlagIncludeGateways;

        var candidates = new List<Candidate>();
        var size = 16u * 1024u;

        // The size the first call asks for can be stale by the time the second one runs, so retry.
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var buffer = Marshal.AllocHGlobal((nint)size);
            try
            {
                var result = GetAdaptersAddresses(AfInet, flags, nint.Zero, buffer, ref size);

                if (result == ErrorBufferOverflow)
                {
                    continue;
                }

                if (result != ErrorSuccess)
                {
                    throw new InvalidOperationException(
                        string.Format(CultureInfo.InvariantCulture, "GetAdaptersAddresses returned {0}", result));
                }

                for (var adapter = (IpAdapterAddresses*)buffer; adapter is not null; adapter = (IpAdapterAddresses*)adapter->Next)
                {
                    if (Qualifies(adapter) is { } candidate)
                    {
                        candidates.Add(candidate);
                    }
                }

                return candidates;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        throw new InvalidOperationException("GetAdaptersAddresses kept asking for a larger buffer.");
    }

    private static Candidate? Qualifies(IpAdapterAddresses* adapter)
    {
        const uint IfOperStatusUp = 1;

        if (adapter->OperStatus != IfOperStatusUp
            || adapter->FirstGatewayAddress == nint.Zero
            || adapter->PhysicalAddressLength == 0)
        {
            return null;
        }

        var address = FirstUnicastIPv4(adapter);
        if (address is null)
        {
            return null;
        }

        // The reference implementation demotes Wi-Fi and treats everything else alike.
        var rank = adapter->IfType == IanaWifi ? 0 : 1;
        var name = Marshal.PtrToStringUni(adapter->FriendlyName) ?? "unnamed";

        return new Candidate(address, name, $"iana {adapter->IfType}, up, gateway", rank);
    }

    /// <summary>
    /// Reads the adapter's first IPv4 unicast address.
    /// </summary>
    private static string? FirstUnicastIPv4(IpAdapterAddresses* adapter)
    {
        const ushort AfInet = 2;

        for (var unicast = (IpAdapterUnicastAddress*)adapter->FirstUnicastAddress;
             unicast is not null;
             unicast = (IpAdapterUnicastAddress*)unicast->Next)
        {
            if (unicast->Sockaddr == nint.Zero || unicast->SockaddrLength < 8)
            {
                continue;
            }

            // sockaddr_in: family, then port, then the four address bytes.
            var sockaddr = (byte*)unicast->Sockaddr;
            if (*(ushort*)sockaddr != AfInet)
            {
                continue;
            }

            return new IPAddress(new ReadOnlySpan<byte>(sockaddr + 4, 4)).ToString();
        }

        return null;
    }

    /// <summary>
    /// The fallback test, using only what WinRT exposes.
    /// </summary>
    /// <remarks>
    /// Weaker than <see cref="EnumerateViaIpHelper"/> on purpose, because there is nothing better
    /// available here: connectivity is the nearest thing to a gateway, and it is not the same thing.
    /// </remarks>
    private static List<Candidate> EnumerateViaWinRT()
    {
        const uint IanaEthernet = 6;

        var candidates = new List<Candidate>();

        foreach (var profile in NetworkInformation.GetConnectionProfiles())
        {
            try
            {
                var adapter = profile.NetworkAdapter;
                if (adapter is null)
                {
                    continue;
                }

                var level = profile.GetNetworkConnectivityLevel();
                if (level < NetworkConnectivityLevel.ConstrainedInternetAccess)
                {
                    continue;
                }

                if (adapter.IanaInterfaceType is not (IanaEthernet or IanaWifi))
                {
                    continue;
                }

                var address = FindIPv4Address(adapter.NetworkAdapterId);
                if (address is null)
                {
                    continue;
                }

                candidates.Add(new Candidate(
                    address,
                    profile.ProfileName ?? "unnamed",
                    $"iana {adapter.IanaInterfaceType}, {level}",
                    adapter.IanaInterfaceType == IanaWifi ? 0 : 1));
            }
            catch (Exception ex)
            {
                // One unreadable profile must not cost us the rest of the list.
                PluginLog.Error("Skipping an unreadable connection profile", ex);
            }
        }

        return candidates;
    }

    /// <summary>
    /// Finds the IPv4 address assigned to the given adapter.
    /// </summary>
    private static string? FindIPv4Address(Guid adapterId)
    {
        foreach (var hostName in NetworkInformation.GetHostNames())
        {
            if (hostName.Type != HostNameType.Ipv4)
            {
                continue;
            }

            if (hostName.IPInformation?.NetworkAdapter is { } adapter
                && adapter.NetworkAdapterId == adapterId)
            {
                return hostName.CanonicalName;
            }
        }

        return null;
    }

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetAdaptersAddresses(
        uint family,
        uint flags,
        nint reserved,
        nint adapterAddresses,
        ref uint sizePointer);

    /// <summary>
    /// <c>IP_ADAPTER_ADDRESSES_LH</c>, truncated after the last field we read.
    /// </summary>
    /// <remarks>
    /// Laid out by hand because the trailing fields are only reachable at the right offsets. The
    /// leading union in the native declaration exists to force eight-byte alignment, which the
    /// <see cref="ulong"/> members here achieve anyway; the inline arrays must stay as byte and
    /// <see cref="uint"/> buffers, since a wider type would be padded and shift everything after it.
    /// </remarks>
    [StructLayout(LayoutKind.Sequential)]
    private struct IpAdapterAddresses
    {
        public uint Length;
        public uint IfIndex;
        public nint Next;
        public nint AdapterName;
        public nint FirstUnicastAddress;
        public nint FirstAnycastAddress;
        public nint FirstMulticastAddress;
        public nint FirstDnsServerAddress;
        public nint DnsSuffix;
        public nint Description;
        public nint FriendlyName;
        public fixed byte PhysicalAddress[8];
        public uint PhysicalAddressLength;
        public uint Flags;
        public uint Mtu;
        public uint IfType;
        public uint OperStatus;
        public uint Ipv6IfIndex;
        public fixed uint ZoneIndices[16];
        public nint FirstPrefix;
        public ulong TransmitLinkSpeed;
        public ulong ReceiveLinkSpeed;
        public nint FirstWinsServerAddress;
        public nint FirstGatewayAddress;
    }

    /// <summary>
    /// <c>IP_ADAPTER_UNICAST_ADDRESS_LH</c>, truncated after its <c>SOCKET_ADDRESS</c>.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct IpAdapterUnicastAddress
    {
        public uint Length;
        public uint Flags;
        public nint Next;
        public nint Sockaddr;
        public int SockaddrLength;
    }

    private sealed record Candidate(string Address, string Name, string Detail, int Rank)
    {
        public override string ToString()
        {
            return string.Format(
                CultureInfo.InvariantCulture,
                "{0} on '{1}' ({2})",
                Address,
                Name,
                Detail);
        }
    }
}
