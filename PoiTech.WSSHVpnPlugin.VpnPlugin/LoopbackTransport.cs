using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Windows.Networking;
using Windows.Networking.Vpn;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// The socket pair the platform is given as the outer tunnel transport, plus the doorbell that
/// makes it call <see cref="SSHVpnPlugin.Decapsulate"/>.
/// </summary>
/// <remarks>
/// <para>
/// The platform takes exclusive ownership of whatever is passed to
/// <see cref="VpnChannel.AssociateTransport"/>: it registers the socket as a ControlChannelTrigger
/// and then reads and writes it itself. A session running over that socket has its bytes stolen —
/// we watched the SSH banner come back corrupted — so the transport handed over here is a dummy
/// that carries nothing, and SSH runs on a socket of its own. See the transport section of
/// CLAUDE.md.
/// </para>
/// <para>
/// The pair is two cross-connected datagram sockets on loopback, never a listener. A listener is
/// what the Windows 8-era documentation warns receives nothing inside an app container, and the
/// cross-connected shape avoids the question entirely. The loopback traffic itself needs no
/// exemption — the app container loopback check passes when both endpoints belong to the same
/// package, which two sockets in one process necessarily do. The platform's side must be a
/// <see cref="Windows.Networking.Sockets.DatagramSocket"/> because that is what
/// <c>AssociateTransport</c> takes; our side is a classic <see cref="Socket"/>, because it only
/// ever sends and the WinRT stream adapter charged an async-operation RCW — plus, sampled live, a
/// reflection-computed interface GUID — for every single ring.
/// </para>
/// <para>
/// Writing to <see cref="RingDoorbell"/> puts a byte on the socket the platform reads, which is
/// what makes it raise a decapsulate event. That is the only way to get inbound packets injected
/// from our own threads: the buffers themselves are carried by a queue, and the event only exists
/// to give us a call on the platform's thread to hand them back on.
/// </para>
/// </remarks>
internal sealed class LoopbackTransport : IOuterTransport
{
    private static readonly byte[] DoorbellPayload = new byte[] { 1 };

    private readonly Windows.Networking.Sockets.DatagramSocket _transport;
    private readonly Socket _back;
    private readonly object _doorbellGate = new();

    private int _disposed;

    private LoopbackTransport(Windows.Networking.Sockets.DatagramSocket transport, Socket back)
    {
        _transport = transport;
        _back = back;
    }

    /// <summary>
    /// Gets the socket to hand to <see cref="VpnChannel.StartWithMainTransport"/>.
    /// </summary>
    public object Transport
    {
        get { return _transport; }
    }

    /// <inheritdoc/>
    public bool CanRingDoorbell
    {
        get { return true; }
    }

    /// <summary>
    /// Associates a fresh socket pair with the channel and cross-connects it.
    /// </summary>
    /// <remarks>
    /// The order is load-bearing. <c>AssociateTransport</c> has to come first and has to see an
    /// unconnected socket: it is what records the transport in the channel, and
    /// <c>StartWithMainTransport</c> checks what it passes against that record — on a channel that
    /// never had one, the check dereferences a null pointer and takes the host process with it.
    /// Connecting before associating instead earns <c>E_OUTOFMEMORY</c> from the broker, which is
    /// not about memory at all.
    /// </remarks>
    public static LoopbackTransport Create(VpnChannel channel)
    {
        ArgumentNullException.ThrowIfNull(channel);

        var localhost = new HostName("127.0.0.1");
        var transport = new Windows.Networking.Sockets.DatagramSocket();
        Socket? back = null;

        try
        {
            channel.AssociateTransport(transport, null);

            back = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            back.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var backPort = ((IPEndPoint)back.LocalEndPoint!).Port;

            // Empty service name: bind to an ephemeral port and read back what we got.
            Wait(transport.BindEndpointAsync(localhost, string.Empty));

            Wait(transport.ConnectAsync(localhost, backPort.ToString(System.Globalization.CultureInfo.InvariantCulture)));
            back.Connect(IPAddress.Loopback, int.Parse(transport.Information.LocalPort, System.Globalization.CultureInfo.InvariantCulture));

            PluginLog.Info(
                $"Loopback transport ready: platform on port {transport.Information.LocalPort}, " +
                $"doorbell on port {backPort}");

            return new LoopbackTransport(transport, back);
        }
        catch
        {
            transport.Dispose();
            back?.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Asks the platform for a decapsulate call.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Fire and forget, and deliberately rung on every batch rather than only when the inbound queue
    /// goes from empty to non-empty. The transition-only form looks cheaper but stalls permanently
    /// if a single ring is ever lost: nothing drains the queue, so it never empties, so no later
    /// enqueue is a transition either. Ringing per batch costs one loopback datagram and bounds the
    /// damage from a lost ring to one batch of latency.
    /// </para>
    /// <para>
    /// Failures are swallowed on purpose. The ring is a hint; losing one delays a batch, whereas
    /// throwing here would fail whatever the caller was really doing.
    /// </para>
    /// </remarks>
    public void RingDoorbell()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        try
        {
            // One writer at a time: the stack rings from its own thread and teardown rings from
            // whichever thread is tearing down. The send itself is one synchronous syscall on a
            // connected datagram socket - the WinRT stream adapter this replaces was sampled
            // creating an async-operation RCW and reflecting out an interface GUID per ring.
            lock (_doorbellGate)
            {
                _ = _back.Send(DoorbellPayload);
            }
        }
        catch (Exception ex)
        {
            PluginLog.Error("Could not ring the decapsulate doorbell", ex);
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        // The transport socket belongs to the platform once the channel started; disposing our
        // reference is all we can do about it either way.
        try
        {
            lock (_doorbellGate)
            {
                _back.Dispose();
            }

            _transport.Dispose();
        }
        catch (Exception ex)
        {
            PluginLog.Error("Failed to close the loopback transport cleanly", ex);
        }
    }

    private static void Wait(Windows.Foundation.IAsyncAction action)
    {
        action.AsTask().GetAwaiter().GetResult();
    }
}
