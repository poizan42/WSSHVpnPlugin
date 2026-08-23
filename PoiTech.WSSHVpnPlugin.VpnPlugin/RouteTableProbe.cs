using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Reads the system routing table, to establish whether the background-task host can.
/// </summary>
/// <remarks>
/// <para>
/// Choosing the tunnel's own client addresses safely is a routing question rather than an
/// addressing one. An assigned address becomes a host route on the tunnel interface, and a host
/// route beats every other prefix length, so what matters is whether anything else already reaches
/// that address — and the routing table is where such a claim is published, which makes reading it
/// before assigning the coordination protocol rather than a heuristic. Addresses alone show only
/// on-link prefixes: a static route, or another VPN's pushed routes, appear in neither the address
/// list nor its prefix lengths.
/// </para>
/// <para>
/// WinRT exposes no routing table, so this calls iphlpapi. Reading the table requires no privilege,
/// which is the reason to expect this to work; what is unestablished is whether the app container
/// permits the call, and the two failures worth telling apart are the module not loading at all and
/// the call being refused once it has.
/// </para>
/// <para>
/// Pointer-form signatures throughout, for the same reason as <see cref="VpnBackgroundTask"/>'s:
/// <c>DisableRuntimeMarshalling</c> forbids by-ref parameters in DllImports, and the
/// <c>MarshalDirectiveException</c> it throws otherwise arrives at runtime.
/// </para>
/// </remarks>
internal static unsafe class RouteTableProbe
{
    private const ushort AddressFamilyUnspecified = 0;
    private const ushort AddressFamilyInternetwork = 2;
    private const ushort AddressFamilyInternetworkV6 = 23;

    /// <summary>How many routes to describe one by one, so the log stays readable.</summary>
    private const int SampleLimit = 12;

    /// <summary>
    /// Reads the table and describes what came back.
    /// </summary>
    public static void Run()
    {
        void* table = null;

        try
        {
            var error = GetIpForwardTable2(AddressFamilyUnspecified, &table);

            if (error != 0)
            {
                PluginLog.Error($"Route table probe: GetIpForwardTable2 refused the call, error {error}");
                return;
            }

            Describe((Table*)table);
        }
        catch (Exception ex)
        {
            // DllNotFoundException or EntryPointNotFoundException here means the container would not
            // give us the module, which is a different answer from the call itself failing above.
            PluginLog.Error("Route table probe: GetIpForwardTable2 could not be called at all", ex);
        }
        finally
        {
            if (table is not null)
            {
                FreeMibTable(table);
            }
        }
    }

    private static void Describe(Table* table)
    {
        var count = table->NumEntries;

        if (count == 0)
        {
            // A successful call returning nothing would be its own answer: the API is reachable and
            // the container hands back an empty view of the system's routes.
            PluginLog.Info("Route table probe: 0 route(s) — the call succeeded and returned nothing");
            return;
        }

        var rows = &table->FirstRow;
        var v4 = 0;
        var v6 = 0;
        var specific = 0;

        for (var i = 0u; i < count; i++)
        {
            var row = rows + i;
            var destination = &row->DestinationPrefix;

            switch (destination->Prefix.Family)
            {
                case AddressFamilyInternetwork:
                    v4++;
                    break;
                case AddressFamilyInternetworkV6:
                    v6++;
                    break;
            }

            // A default route reaches everything and so excludes nothing; the count that bears on
            // choosing an address is of the routes more specific than one.
            if (destination->PrefixLength > 0)
            {
                specific++;
            }

            if (i < SampleLimit)
            {
                PluginLog.Info(
                    $"Route table probe: {FormatPrefix(destination)} metric {row->Metric} " +
                    $"on interface {row->InterfaceIndex}");
            }
        }

        var elided = count > SampleLimit ? $", {count - SampleLimit} not listed" : string.Empty;
        PluginLog.Info(
            $"Route table probe: {count} route(s) — {v4} v4, {v6} v6, " +
            $"{specific} more specific than a default{elided}");
    }

    /// <summary>
    /// Formats a destination prefix, reading the address out of the family's own sockaddr layout.
    /// </summary>
    private static string FormatPrefix(IpAddressPrefix* prefix)
    {
        var bytes = (byte*)&prefix->Prefix;

        switch (prefix->Prefix.Family)
        {
            case AddressFamilyInternetwork:
                // SOCKADDR_IN carries the address after the family and port.
                var v4 = BinaryPrimitives.ReadUInt32BigEndian(new ReadOnlySpan<byte>(bytes + 4, 4));
                return $"{IpAddr.FromV4(v4).Format()}/{prefix->PrefixLength}";

            case AddressFamilyInternetworkV6:
                // SOCKADDR_IN6 carries it after the family, port and flow info.
                return $"{IpAddr.ReadV6(new ReadOnlySpan<byte>(bytes + 8, 16)).Format()}/{prefix->PrefixLength}";

            default:
                return $"family {prefix->Prefix.Family}/{prefix->PrefixLength}";
        }
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
    /// <see cref="FormatPrefix"/> still reads the address by pointer, since which offset holds it
    /// is what the union decides.
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
