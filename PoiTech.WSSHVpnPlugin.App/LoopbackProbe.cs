using System;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;

namespace PoiTech.WSSHVpnPlugin.App;

/// <summary>
/// Proves that a cross-connected pair of loopback datagram sockets can actually exchange traffic
/// inside this package's app container.
/// </summary>
/// <remarks>
/// <para>
/// The VPN plug-in hands the platform exactly such a pair as its outer tunnel transport, and rings
/// one end of it to make the platform ask for inbound packets. If loopback were blocked, that would
/// fail — and it would fail from inside a background task, at the same moment as half a dozen other
/// things that can also fail, with one activation per attempt to find out which.
/// </para>
/// <para>
/// Running the same exchange here costs nothing and separates the two. The check that matters is on
/// the package identity, which is the same in this process as in the plug-in's, so a pass here means
/// loopback is not what broke.
/// </para>
/// </remarks>
internal static class LoopbackProbe
{
    private static readonly TimeSpan ReceiveTimeout = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Exchanges one datagram each way and describes what happened.
    /// </summary>
    public static async Task<string> RunAsync()
    {
        var localhost = new HostName("127.0.0.1");

        using var transport = new DatagramSocket();
        using var back = new DatagramSocket();
        using var received = new SemaphoreSlim(0);

        var payload = 0;

        transport.MessageReceived += (sender, args) =>
        {
            using var reader = args.GetDataReader();
            if (reader.UnconsumedBufferLength > 0)
            {
                payload = reader.ReadByte();
            }

            _ = received.Release();
        };

        // The same order the plug-in uses: bind both to ephemeral ports, then cross-connect. No
        // listener is involved anywhere, which is deliberate.
        await transport.BindEndpointAsync(localhost, string.Empty);
        await back.BindEndpointAsync(localhost, string.Empty);

        await transport.ConnectAsync(localhost, back.Information.LocalPort);
        await back.ConnectAsync(localhost, transport.Information.LocalPort);

        var writer = new DataWriter(back.OutputStream);
        writer.WriteByte(0x2A);
        _ = await writer.StoreAsync();
        _ = writer.DetachStream();

        if (!await received.WaitAsync(ReceiveTimeout))
        {
            return "loopback FAILED: nothing arrived within 2s "
                + $"(ports {back.Information.LocalPort} -> {transport.Information.LocalPort})";
        }

        return payload == 0x2A
            ? $"loopback ok: {back.Information.LocalPort} -> {transport.Information.LocalPort}"
            : $"loopback FAILED: expected 42 but received {payload}";
    }
}
