using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Connectivity;
using Windows.Networking.Sockets;

namespace PoiTech.WSSHVpnPlugin.App;

/// <summary>
/// Drives <see cref="ControlChannelTrigger"/> directly, outside any VPN channel.
/// </summary>
/// <remarks>
/// <para>
/// <c>VpnChannel.AssociateTransport</c> registers the transport as a control channel trigger, and
/// <c>StartWithMainTransport</c> then calls <see cref="ControlChannelTrigger.WaitForPushEnabled"/> on
/// it. That call is what fails, with <c>E_OUTOFMEMORY</c> propagated from the trigger broker over
/// RPC. Everything about the failure therefore belongs to the trigger, not to the VPN.
/// </para>
/// <para>
/// This matters because a VPN channel is single-shot — one activation yields one experiment, and a
/// deploy each time — whereas a trigger can be created and thrown away in a loop. Reproducing the
/// same failure here turns "one guess per deploy" into a matrix we can run on a button press, and
/// tells us which property of the socket the broker objects to.
/// </para>
/// </remarks>
internal static class CctProbe
{
    /// <summary>The shortest keep-alive the API accepts.</summary>
    private const uint KeepAliveMinutes = 15;

    /// <summary>
    /// Runs every combination worth trying and describes what each one did.
    /// </summary>
    public static async Task<string> RunAsync()
    {
        var report = new StringBuilder();
        var loopback = new HostName("127.0.0.1");
        var physical = FindPhysicalAddress();

        report.AppendLine("ControlChannelTrigger probe (no VPN channel involved):");

        foreach (var resourceType in new[]
                 {
                     ControlChannelTriggerResourceType.RequestSoftwareSlot,
                     ControlChannelTriggerResourceType.RequestHardwareSlot,
                 })
        {
            report.AppendLine($"  {await ProbeAsync($"datagram/loopback/{resourceType}", loopback, resourceType)}");

            if (physical is not null)
            {
                report.AppendLine($"  {await ProbeAsync($"datagram/{physical.CanonicalName}/{resourceType}", physical, resourceType)}");
            }
        }

        // Whether the broker objects to the socket at all, or only to a connected one.
        report.AppendLine($"  {await ProbeAsync("datagram/loopback/unconnected", loopback, ControlChannelTriggerResourceType.RequestSoftwareSlot, connect: false)}");

        return report.ToString().TrimEnd();
    }

    /// <summary>
    /// Builds a cross-connected datagram pair, registers the first as a trigger transport, and asks
    /// the broker to push-enable it.
    /// </summary>
    private static async Task<string> ProbeAsync(
        string label,
        HostName address,
        ControlChannelTriggerResourceType resourceType,
        bool connect = true)
    {
        ControlChannelTrigger? trigger = null;
        DatagramSocket? transport = null;
        DatagramSocket? back = null;

        // Which call failed matters more than that one did: a denial at construction is an
        // entitlement problem, a denial at WaitForPushEnabled is the broker's answer about the
        // socket, and they call for opposite fixes.
        var step = "construct sockets";

        try
        {
            transport = new DatagramSocket();
            back = new DatagramSocket();

            // A distinct id per attempt: reusing one that is still registered is its own failure.
            step = "new ControlChannelTrigger";
            trigger = new ControlChannelTrigger($"wsshvpn-probe-{Guid.NewGuid():N}", KeepAliveMinutes, resourceType);

            // The same order the plug-in uses: register while unconnected, bind, then cross-connect.
            step = "UsingTransport";
            trigger.UsingTransport(transport);

            step = "BindEndpointAsync";
            await transport.BindEndpointAsync(address, string.Empty);
            await back.BindEndpointAsync(address, string.Empty);

            if (connect)
            {
                step = "ConnectAsync";
                await transport.ConnectAsync(address, back.Information.LocalPort);
                await back.ConnectAsync(address, transport.Information.LocalPort);
            }

            step = "WaitForPushEnabled";
            var status = trigger.WaitForPushEnabled();
            return $"{label}: WaitForPushEnabled -> {status}";
        }
        catch (Exception ex)
        {
            return $"{label}: [{step}] 0x{ex.HResult:X8} {ex.GetType().Name}: {ex.Message.Split('\n')[0].Trim()}";
        }
        finally
        {
            trigger?.Dispose();
            back?.Dispose();
            transport?.Dispose();
        }
    }

    /// <summary>
    /// Finds an IPv4 address on a real adapter, to test whether the broker objects to loopback.
    /// </summary>
    private static HostName? FindPhysicalAddress()
    {
        var candidates = new List<HostName>();

        foreach (var hostName in NetworkInformation.GetHostNames())
        {
            if (hostName.Type == HostNameType.Ipv4
                && hostName.IPInformation?.NetworkAdapter is { } adapter
                && adapter.IanaInterfaceType is 6 or 71)
            {
                candidates.Add(hostName);
            }
        }

        return candidates.Count > 0 ? candidates[0] : null;
    }
}
