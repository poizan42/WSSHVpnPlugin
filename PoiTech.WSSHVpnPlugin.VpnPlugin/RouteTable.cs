using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;

using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Reads the system routing table: the prefixes this machine already reaches.
/// </summary>
/// <remarks>
/// <para>
/// Choosing the tunnel's own client addresses is a routing question rather than an addressing one.
/// An assigned address becomes a host route on the tunnel interface, and a host route beats every
/// other prefix length, so what matters is whether anything else already reaches that address — and
/// the routing table is where such a claim is published, which makes reading it before assigning the
/// coordination protocol rather than a heuristic. The address list is not a substitute: it shows
/// on-link prefixes only, so a static route or another VPN's pushed routes appear in neither it nor
/// its prefix lengths, and it filters IPv6 link-locals so thoroughly that a machine with eleven of
/// them reports none at all.
/// </para>
/// <para>
/// WinRT exposes no routing table, so this calls iphlpapi. Reading it needs no privilege and the app
/// container permits it — measured from inside the background-task host, 72 routes in 8 ms against
/// the address list's 132 ms for five entries.
/// </para>
/// <para>
/// Pointer-form signatures throughout, for the same reason as <see cref="VpnBackgroundTask"/>'s:
/// <c>DisableRuntimeMarshalling</c> forbids by-ref parameters in DllImports, and the
/// <c>MarshalDirectiveException</c> it throws otherwise arrives at runtime.
/// </para>
/// </remarks>
internal static unsafe class RouteTable
{
    private const ushort AddressFamilyUnspecified = 0;
    private const ushort AddressFamilyInternetwork = 2;
    private const ushort AddressFamilyInternetworkV6 = 23;

    /// <summary>
    /// Reads the destination prefixes of every route the system holds.
    /// </summary>
    /// <returns>
    /// The prefixes, or <see langword="null"/> when the table could not be read at all — which the
    /// caller must treat as "no information" rather than "nothing is claimed".
    /// </returns>
    /// <remarks>
    /// The two ways this can fail are logged separately rather than collapsed into the null, because
    /// they mean different things: the module not loading is the container refusing us, while an
    /// error code is the call itself declining once it has.
    /// </remarks>
    public static IReadOnlyList<IpPrefix>? TryRead()
    {
        void* table = null;

        try
        {
            var error = GetIpForwardTable2(AddressFamilyUnspecified, &table);

            if (error != 0)
            {
                PluginLog.Error($"The routing table could not be read: GetIpForwardTable2 returned {error}");
                return null;
            }

            return Collect((Table*)table);
        }
        catch (Exception ex)
        {
            // DllNotFoundException or EntryPointNotFoundException here means the container would not
            // give us the module, which is a different answer from the call declining above.
            PluginLog.Error("The routing table could not be read: GetIpForwardTable2 is unavailable", ex);
            return null;
        }
        finally
        {
            if (table is not null)
            {
                FreeMibTable(table);
            }
        }
    }

    /// <summary>
    /// Turns the rows into prefixes, skipping any address family this stack does not carry.
    /// </summary>
    private static List<IpPrefix> Collect(Table* table)
    {
        var count = table->NumEntries;
        var prefixes = new List<IpPrefix>((int)count);

        if (count == 0)
        {
            // Distinguished from a failure by the caller getting a list rather than null: the table
            // is readable and this machine genuinely routes nothing.
            PluginLog.Info("Routing table: 0 route(s)");
            return prefixes;
        }

        var rows = &table->FirstRow;
        var v4 = 0;
        var v6 = 0;

        for (var i = 0u; i < count; i++)
        {
            var destination = &(rows + i)->DestinationPrefix;
            var bytes = (byte*)&destination->Prefix;

            switch (destination->Prefix.Family)
            {
                case AddressFamilyInternetwork:
                    // SOCKADDR_IN carries the address after the family and port.
                    var address = BinaryPrimitives.ReadUInt32BigEndian(new ReadOnlySpan<byte>(bytes + 4, 4));
                    prefixes.Add(new IpPrefix(IpAddr.FromV4(address), destination->PrefixLength));
                    v4++;
                    break;

                case AddressFamilyInternetworkV6:
                    // SOCKADDR_IN6 carries it after the family, port and flow info.
                    var address6 = IpAddr.ReadV6(new ReadOnlySpan<byte>(bytes + 8, 16));
                    prefixes.Add(new IpPrefix(address6, destination->PrefixLength));
                    v6++;
                    break;
            }
        }

        PluginLog.Info($"Routing table: {count} route(s) — {v4} v4, {v6} v6");
        return prefixes;
    }

    /// <summary>
    /// <c>SOCKADDR_INET</c>, laid out as its largest union member <c>SOCKADDR_IN6</c>: 28 bytes.
    /// </summary>
    /// <remarks>
    /// The fields are spelled out rather than replaced by a sized blob because the blob gets the
    /// size right and the <em>alignment</em> wrong — a lone <c>ushort</c> aligns the struct to 2,
    /// while the real one aligns to 4 on its <c>ULONG</c> members, which shifts every field after
    /// <see cref="IpForwardRow2.DestinationPrefix"/> by two bytes and leaves
    /// <c>sizeof(MIB_IPFORWARD_ROW2)</c> correct anyway, the trailing padding absorbing it.
    /// <see cref="Collect"/> still reads the address by pointer, since which offset holds it is what
    /// the union decides.
    /// </remarks>
    [StructLayout(LayoutKind.Sequential)]
    private struct SockAddrInet
    {
        public ushort Family;
        public ushort Port;

        /// <summary>Flow info for v6; for v4 these four bytes are the address itself.</summary>
        public uint FlowInfoOrV4Address;

        public fixed byte V6Address[16];
        public uint ScopeId;
    }

    /// <summary><c>IP_ADDRESS_PREFIX</c>.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct IpAddressPrefix
    {
        public SockAddrInet Prefix;
        public byte PrefixLength;
    }

    /// <summary><c>MIB_IPFORWARD_ROW2</c>.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct IpForwardRow2
    {
        public ulong InterfaceLuid;
        public uint InterfaceIndex;
        public IpAddressPrefix DestinationPrefix;
        public SockAddrInet NextHop;
        public byte SitePrefixLength;
        public uint ValidLifetime;
        public uint PreferredLifetime;
        public uint Metric;
        public uint Protocol;
        public byte Loopback;
        public byte AutoconfigureAddress;
        public byte Publish;
        public byte Immortal;
        public uint Age;
        public uint Origin;
    }

    /// <summary>
    /// <c>MIB_IPFORWARD_TABLE2</c>: a count then the rows. The first row is declared rather than
    /// assumed to follow the count immediately, so the compiler supplies the padding the row's own
    /// eight-byte alignment demands.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct Table
    {
        public uint NumEntries;
        public IpForwardRow2 FirstRow;
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetIpForwardTable2(ushort family, void** table);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern void FreeMibTable(void* memory);
}
