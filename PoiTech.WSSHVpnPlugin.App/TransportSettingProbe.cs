using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Windows.Networking.Connectivity;

namespace PoiTech.WSSHVpnPlugin.App;

/// <summary>
/// Runs the socket IOCTL that the VPN platform runs on its outer tunnel transport, and reports what
/// the operating system says about it.
/// </summary>
/// <remarks>
/// <para>
/// <c>VpnChannel.StartWithMainTransport</c> fails with <c>0x8007000E</c>, which looks like
/// <c>E_OUTOFMEMORY</c> and is nothing of the kind. Disassembly of <c>Windows.Networking.dll</c>
/// shows the platform reaching the transport socket's own settings interface and issuing
/// <c>WSAIoctl(SIO_APPLY_TRANSPORT_SETTING)</c> for the real-time notification capability, then
/// wrapping any failure as <c>0x80070000 | (WSAGetLastError() &amp; 0xFFFF)</c>. So the HRESULT is a
/// disguised socket error 14, and the operation is an ordinary IOCTL we can issue ourselves.
/// </para>
/// <para>
/// That matters because a VPN channel is single-shot and needs a deploy and an activation per
/// attempt, whereas this is a loop. The question it exists to answer is whether the capability is
/// refused because the socket sits on loopback — which has no wake-capable interface behind it — in
/// which case the dummy transport has to live on a real adapter instead.
/// </para>
/// </remarks>
internal static class TransportSettingProbe
{
    /// <summary>Applies a transport setting to a socket.</summary>
    private const int SioApplyTransportSetting = unchecked((int)0x98000013);

    /// <summary>Queries a transport setting on a socket.</summary>
    private const int SioQueryTransportSetting = unchecked((int)0x98000014);

    /// <summary>
    /// <c>REAL_TIME_NOTIFICATION_CAPABILITY</c> — the setting the platform asks for.
    /// </summary>
    private static readonly Guid RealTimeNotificationCapability =
        new("6B59819A-5CAE-492D-A901-2A3C2C50164F");

    /// <summary>
    /// Tries the setting on every socket shape worth comparing.
    /// </summary>
    public static string Run()
    {
        var report = new StringBuilder();
        report.AppendLine("SIO_APPLY_TRANSPORT_SETTING / RealTimeNotificationCapability:");

        // Every local address, not a guessed "best" one: the first pass picked a Hyper-V switch
        // address and left the real adapter untested, which is exactly the comparison that matters.
        foreach (var address in LocalAddresses())
        {
            report.AppendLine($"  {Probe($"udp  {address}", address, ProtocolType.Udp, connected: false)}");
            report.AppendLine($"  {Probe($"udp  {address}", address, ProtocolType.Udp, connected: true)}");

            // A connected TCP socket is the shape this capability is documented for, so it is the
            // one most likely to be accepted; "not supported for the type of object" on datagram
            // sockets hints the setting may be TCP-only.
            report.AppendLine($"  {Probe($"tcp  {address}", address, ProtocolType.Tcp, connected: true)}");
        }

        return report.ToString().TrimEnd();
    }

    /// <summary>
    /// Lists loopback plus every IPv4 address the machine has, with the owning adapter named.
    /// </summary>
    private static List<IPAddress> LocalAddresses()
    {
        var addresses = new List<IPAddress> { IPAddress.Loopback };

        foreach (var hostName in NetworkInformation.GetHostNames())
        {
            if (hostName.Type == Windows.Networking.HostNameType.Ipv4
                && IPAddress.TryParse(hostName.CanonicalName, out var parsed)
                && !addresses.Contains(parsed))
            {
                addresses.Add(parsed);
            }
        }

        return addresses;
    }

    /// <summary>
    /// Builds one socket and asks for the capability on it.
    /// </summary>
    private static string Probe(string label, IPAddress address, ProtocolType protocol, bool connected)
    {
        var suffix = connected ? "connected" : "bound only";

        Socket? socket = null;
        Socket? peer = null;
        Socket? listener = null;

        try
        {
            var socketType = protocol == ProtocolType.Tcp ? SocketType.Stream : SocketType.Dgram;

            socket = new Socket(AddressFamily.InterNetwork, socketType, protocol);

            if (protocol == ProtocolType.Tcp && connected)
            {
                // A real established connection, so the setting is applied to the shape it was
                // designed for rather than to a socket that has never carried anything.
                listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                listener.Bind(new IPEndPoint(address, 0));
                listener.Listen(1);

                socket.Bind(new IPEndPoint(address, 0));
                socket.Connect(listener.LocalEndPoint!);
                peer = listener.Accept();
            }
            else
            {
                socket.Bind(new IPEndPoint(address, 0));

                if (connected && protocol == ProtocolType.Udp)
                {
                    peer = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                    peer.Bind(new IPEndPoint(address, 0));
                    socket.Connect(peer.LocalEndPoint!);
                    peer.Connect(socket.LocalEndPoint!);
                }
            }

            // REAL_TIME_NOTIFICATION_SETTING_INPUT: the setting id, then the broker event id.
            var input = new byte[32];
            _ = RealTimeNotificationCapability.TryWriteBytes(input.AsSpan(0, 16));
            _ = Guid.NewGuid().TryWriteBytes(input.AsSpan(16, 16));

            _ = socket.IOControl(SioApplyTransportSetting, input, null);

            // If applying worked, find out what the query reports back.
            var queryInput = new byte[16];
            _ = RealTimeNotificationCapability.TryWriteBytes(queryInput);
            var queryOutput = new byte[4];
            _ = socket.IOControl(SioQueryTransportSetting, queryInput, queryOutput);

            return $"{label} ({suffix}): APPLIED, query -> {BitConverter.ToInt32(queryOutput)}";
        }
        catch (SocketException ex)
        {
            return $"{label} ({suffix}): {ex.SocketErrorCode} native={ex.NativeErrorCode} - {ex.Message}";
        }
        catch (Exception ex)
        {
            return $"{label} ({suffix}): {ex.GetType().Name} 0x{ex.HResult:X8} - {ex.Message}";
        }
        finally
        {
            peer?.Dispose();
            listener?.Dispose();
            socket?.Dispose();
        }
    }
}
