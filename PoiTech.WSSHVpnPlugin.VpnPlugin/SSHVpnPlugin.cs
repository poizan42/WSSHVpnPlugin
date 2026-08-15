using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
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
/// The platform is given a loopback dummy socket as its outer tunnel transport, because it takes
/// exclusive ownership of whatever it is given; see <see cref="LoopbackTransport"/>. Inbound packets
/// come back through <see cref="Decapsulate"/>, which the doorbell on that socket is what summons.
/// </para>
/// <para>
/// The instance is long-lived: the background task host creates it once and reuses it for every
/// event on the channel. See <see cref="VpnBackgroundTask"/>.
/// </para>
/// </remarks>
public sealed class SSHVpnPlugin : IVpnPlugIn
{
    /// <summary>
    /// How long to wait between reporting outbound packet failures. <see cref="Encapsulate"/> runs
    /// at line rate, so an unconditional log there fills the disk on any systematic failure.
    /// </summary>
    private const long FailureReportIntervalMs = 10_000;

    /// <summary>
    /// How many times <see cref="Decapsulate"/> re-checks an empty queue before giving up on the
    /// batch, absorbing the race between a packet being queued and the doorbell being rung.
    /// </summary>
    private const int EmptyQueueSpins = 8;

    /// <summary>
    /// How long <see cref="Disconnect"/> gives the platform to call <see cref="Decapsulate"/> one
    /// last time before reporting that it did not.
    /// </summary>
    private static readonly TimeSpan StopWatchdogDelay = TimeSpan.FromSeconds(2);

    private readonly object _stateGate = new();

    private SshVpnConnection? _connection;
    private IOuterTransport? _transport;
    private InboundPacketQueue? _inbound;
    private M0Spike? _spike;
    private Timer? _stopWatchdog;
    private int _channelStopped;
    private int _decapsulateCalls;
    private int _encapsulateCalls;

    private long _encapsulateFailureCount;
    private long _lastFailureReportTicks;
    private Exception? _lastEncapsulateFailure;

    /// <inheritdoc/>
    public void Connect(VpnChannel channel)
    {
        ArgumentNullException.ThrowIfNull(channel);

        try
        {
            // This instance outlives an activation, so a second connect inherits whatever the last
            // one left behind. Clear it before anything else, or the old session and its sockets
            // stay alive behind the new ones.
            ResetState();

            var configuration = SshVpnConfiguration.FromChannelConfiguration(channel.Configuration);
            PluginLog.Info($"Connecting to {configuration.Host}:{configuration.Port}");

            // A key-based profile that already names its user needs nothing from the user, and
            // asking anyway would put a prompt in front of a background task for no reason.
            var needsCredentials = configuration.PrivateKeyPath is null || configuration.UserName is null;

            var credential = needsCredentials
                ? channel.RequestCredentials(
                    VpnCredentialType.UsernamePassword,
                    isRetry: false,
                    isSingleSignOnCredential: false,
                    certificate: null)
                : null;

            var userName = configuration.UserName ?? credential?.PasskeyCredential?.UserName;
            if (string.IsNullOrEmpty(userName))
            {
                throw new InvalidOperationException("No SSH user name was configured or supplied.");
            }

            // SSH runs on a socket of its own, bound to a physical interface so that it does not
            // route into the tunnel it is about to carry.
            var connection = SshVpnConnection.Establish(
                configuration,
                userName,
                credential?.PasskeyCredential?.Password ?? string.Empty,
                OutboundInterface.Select(configuration.NetworkAdapter));

            IOuterTransport transport = configuration.RemoteDummyTransport
                ? RemoteDummyTransport.Create(channel, configuration.Host, configuration.Port)
                : LoopbackTransport.Create(channel);

            var inbound = new InboundPacketQueue(channel);

            lock (_stateGate)
            {
                _connection = connection;
                _transport = transport;
                _inbound = inbound;
                _channelStopped = 0;
            }

            if (configuration.StartDelaySeconds > 0)
            {
                PluginLog.Info(
                    $"Waiting {configuration.StartDelaySeconds}s before Start so a debugger can attach "
                    + $"to this process (pid {Environment.ProcessId}).");
                Thread.Sleep(TimeSpan.FromSeconds(configuration.StartDelaySeconds));
            }

            // Everything the platform might immediately call into has to exist before this: it may
            // ask for packets as soon as the channel starts.
            StartChannel(channel, configuration, transport);

            // The packet path needs the queue and the doorbell, neither of which exists until the
            // channel has started.
            connection.AttachPacketPath(inbound, transport, configuration.TracerDestination);

            if (configuration.SpikeProbe)
            {
                var spike = M0Spike.Start(channel, connection, inbound, transport, configuration.ClientIPv4);
                lock (_stateGate)
                {
                    _spike = spike;
                }
            }
        }
        catch (Exception ex)
        {
            PluginLog.Error("Connect failed", ex);
            ResetState();

            // TerminateConnection, not SetErrorMessage: the latter is documented as not supported.
            channel.TerminateConnection(ex.Message);
        }
    }

    /// <summary>
    /// Starts the channel over the loopback dummy transport.
    /// </summary>
    /// <remarks>
    /// Exactly one attempt: the channel is single-shot, and a second call after a rejected one
    /// returns <c>E_ILLEGAL_METHOD_CALL</c> rather than being retried on its merits.
    /// </remarks>
    private static void StartChannel(VpnChannel channel, SshVpnConfiguration configuration, IOuterTransport transport)
    {
        // Every other difference from a known-good implementation has now been eliminated by
        // experiment, so the arguments are the last candidate. These are Maple's exact values,
        // including an assigned IPv6 address and IPv6 routes we have no stack for: the point is to
        // replicate something that ships, not to be correct. If this is what starts the channel, the
        // differences get bisected from here.
        var ipv4 = new List<HostName> { new HostName(configuration.ClientIPv4) };
        var ipv6 = configuration.AssignIPv6
            ? new List<HostName> { new HostName("fd00::2") }
            : new List<HostName>();
        var mtu = configuration.LargeFrameSize ? 1500u : configuration.Mtu;
        var frameSize = configuration.LargeFrameSize ? 1512u : GetMaxFrameSize(configuration.Mtu);

        try
        {
            channel.StartWithMainTransport(
                ipv4,
                ipv6,
                null,                                                          // interface id
                BuildRouteAssignment(configuration),
                BuildDomainNameAssignment(configuration),
                mtu,
                frameSize,
                false,                                                         // reserved
                transport.Transport);

            PluginLog.Info($"StartWithMainTransport accepted (mtu {mtu}, frame {frameSize}, ipv6 {ipv6.Count})");
        }
        catch (Exception ex)
        {
            PluginLog.Error($"StartWithMainTransport rejected: 0x{ex.HResult:X8}", ex);
            throw;
        }
    }

    /// <summary>
    /// Gets the frame size to advertise for the given MTU.
    /// </summary>
    /// <remarks>
    /// The platform sizes the send buffer pool from this and documents a hard ceiling of 1500,
    /// reducing either the MTU or the encapsulation overhead if the sum would exceed it. We add no
    /// encapsulation of our own — the SSH session owns the wire — so the MTU alone would do; the
    /// clamp exists so that a profile configuring a larger MTU degrades rather than being rejected.
    /// </remarks>
    private static uint GetMaxFrameSize(uint mtu)
    {
        const uint PlatformMaxFrameSize = 1500;
        const uint HeaderRoom = 128;

        return Math.Min(mtu + HeaderRoom, PlatformMaxFrameSize);
    }

    /// <summary>
    /// Reports outbound packet failures, at most once per <see cref="FailureReportIntervalMs"/>.
    /// </summary>
    /// <param name="failures">The number of failures in the batch just processed.</param>
    private void ReportEncapsulateFailures(int failures)
    {
        var total = Interlocked.Add(ref _encapsulateFailureCount, failures);

        var now = Environment.TickCount64;
        var previous = Interlocked.Read(ref _lastFailureReportTicks);
        if (now - previous < FailureReportIntervalMs)
        {
            return;
        }

        // Losing the race just means another thread reports instead.
        if (Interlocked.CompareExchange(ref _lastFailureReportTicks, now, previous) != previous)
        {
            return;
        }

        PluginLog.Error(
            string.Format(CultureInfo.InvariantCulture, "{0} outbound packet(s) failed so far", total),
            _lastEncapsulateFailure);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// <para>
    /// Deliberately does not call <see cref="VpnChannel.Stop"/>. Buffers the platform has lent us
    /// and not had back block the VPN background task, and the platform kills the whole host process
    /// when it stops responding. Instead the inbound queue is closed and the doorbell rung once
    /// more, so that <see cref="Decapsulate"/> returns what is outstanding and stops the channel
    /// itself once there is nothing left.
    /// </para>
    /// <para>
    /// Whether the platform actually delivers that last call is exactly what M0′ is meant to find
    /// out, so the watchdog reports which way it went rather than papering over it.
    /// </para>
    /// </remarks>
    public void Disconnect(VpnChannel channel)
    {
        ArgumentNullException.ThrowIfNull(channel);

        PluginLog.Info("Disconnecting");
        try
        {
            IOuterTransport? transport;
            InboundPacketQueue? inbound;

            lock (_stateGate)
            {
                transport = _transport;
                inbound = _inbound;
            }

            // Stop producing before stopping the session, so nothing tries to queue a packet into a
            // connection that is going away.
            inbound?.Close();
            CloseSession();

            // One last ring, after closing: this is what gets us the call in which the queue is
            // observed drained and the channel is stopped.
            transport?.RingDoorbell();
            ArmStopWatchdog(channel);
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
    /// <para>
    /// Nothing is added to <paramref name="encapsulatedPackets"/>: the platform's send path is
    /// only used when the plug-in wraps packets for a transport the platform owns. Here the SSH
    /// session owns the wire, so the packets are handed to the user-space stack and this method
    /// returns an empty list.
    /// </para>
    /// <para>
    /// Each buffer is taken off the front of <paramref name="packets"/> and appended back to the
    /// <em>same</em> list once its contents have been copied out — not to
    /// <paramref name="encapsulatedPackets"/>, which stays empty. That is what both shipping
    /// implementations do, and it is not interchangeable with enumerating the list: merely reading
    /// through it left the platform delivering one burst of packets during connect and nothing
    /// afterwards, which is what a plug-in that never returns its buffers looks like.
    /// </para>
    /// </remarks>
    public void Encapsulate(VpnChannel channel, VpnPacketBufferList packets, VpnPacketBufferList encapsulatedPackets)
    {
        ArgumentNullException.ThrowIfNull(packets);

        var connection = GetConnection();
        LogFirstEncapsulateCalls(packets, connection);

        if (connection is null)
        {
            return;
        }

        var spike = GetSpike();
        var failures = 0;

        // Size is captured first: the list is rotated, not drained, so re-reading it would loop.
        var count = packets.Size;
        for (uint i = 0; i < count; i++)
        {
            var buffer = packets.RemoveAtBegin();
            try
            {
                spike?.SampleOutbound(VpnPacketBufferAccess.GetSpan(buffer).Slice(0, checked((int)buffer.Buffer.Length)));

                // TODO: hand the IP packet to the user-space TCP/IP stack, which maps each TCP
                // flow onto an SSH direct-tcpip channel.
                connection.SendOutbound(buffer);
            }
            catch (Exception ex)
            {
                // Deliberately not logged per packet: a systematic failure here runs at line rate
                // and would fill the disk. Count them and log once for the batch instead.
                failures++;
                _lastEncapsulateFailure = ex;
            }
            finally
            {
                // Unconditional: a buffer dropped on a failure is one the platform never gets back.
                packets.Append(buffer);
            }
        }

        if (failures > 0)
        {
            ReportEncapsulateFailures(failures);
        }
    }

    /// <summary>
    /// Hands the platform the inbound packets waiting to be injected.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <paramref name="encapBuffer"/> is ignored: nothing is ever sent over the dummy transport, so
    /// the only thing that arrives on it is our own doorbell byte. The call itself is the point —
    /// it is the one place we are allowed to give the platform buffers back on the inbound path.
    /// </para>
    /// <para>
    /// The packets are already written into the platform's own buffers by whoever produced them, so
    /// there is nothing to copy here; appending a buffer is what returns it.
    /// </para>
    /// </remarks>
    public void Decapsulate(
        VpnChannel channel,
        VpnPacketBuffer encapBuffer,
        VpnPacketBufferList decapsulatedPackets,
        VpnPacketBufferList controlPacketsToSend)
    {
        var inbound = GetInbound();
        if (inbound is null || decapsulatedPackets is null)
        {
            return;
        }

        LogFirstDecapsulateCalls(encapBuffer);

        var spins = 0;
        var appended = 0;

        while (true)
        {
            if (inbound.TryDequeue(out var buffer))
            {
                decapsulatedPackets.Append(buffer);
                appended++;
                spins = 0;
                continue;
            }

            // Nothing left, and nothing more coming: this is the call Disconnect asked for.
            if (inbound.IsFinished)
            {
                StopChannel(channel, $"the inbound queue drained after disconnect, {appended} returned");
                return;
            }

            if (++spins >= EmptyQueueSpins)
            {
                return;
            }
        }
    }

    /// <summary>
    /// Logs the first few encapsulate calls, before anything can return early.
    /// </summary>
    /// <remarks>
    /// The interesting case is the absence of these lines: with the tunnel up and traffic routed to
    /// it, no encapsulate call at all means the platform is not offering us the send path, which is a
    /// different problem from us dropping what it offers.
    /// </remarks>
    private void LogFirstEncapsulateCalls(VpnPacketBufferList packets, SshVpnConnection? connection)
    {
        const int LogBudget = 5;

        var call = Interlocked.Increment(ref _encapsulateCalls);
        if (call > LogBudget)
        {
            return;
        }

        PluginLog.Info(
            string.Format(
                CultureInfo.InvariantCulture,
                "Encapsulate called (#{0}), {1} packet(s), connection {2}",
                call,
                packets.Size,
                connection is null ? "MISSING" : "present"));
    }

    /// <summary>
    /// Logs the first few decapsulate calls, which is how we find out whether the doorbell works at
    /// all and what the platform hands us when it rings.
    /// </summary>
    private void LogFirstDecapsulateCalls(VpnPacketBuffer? encapBuffer)
    {
        const int LogBudget = 5;

        var call = Interlocked.Increment(ref _decapsulateCalls);
        if (call > LogBudget)
        {
            return;
        }

        var length = encapBuffer?.Buffer?.Length;
        PluginLog.Info(
            string.Format(
                CultureInfo.InvariantCulture,
                "Decapsulate called (#{0}), encapBuffer {1}",
                call,
                length is null ? "absent" : $"{length} bytes"));
    }

    /// <summary>
    /// Supplies a keep-alive payload for the platform to send on an idle tunnel.
    /// </summary>
    /// <remarks>
    /// SSH runs its own keep-alive (<see cref="Renci.SshNet.BaseClient.KeepAliveInterval"/>), and
    /// the transport the platform would send this on is a dummy that carries nothing, so no
    /// platform-level keep-alive packet is produced.
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

    private InboundPacketQueue? GetInbound()
    {
        lock (_stateGate)
        {
            return _inbound;
        }
    }

    private M0Spike? GetSpike()
    {
        lock (_stateGate)
        {
            return _spike;
        }
    }

    /// <summary>
    /// Stops the spike and the SSH session, leaving the channel and its transport alone.
    /// </summary>
    private void CloseSession()
    {
        SshVpnConnection? connection;
        M0Spike? spike;

        lock (_stateGate)
        {
            connection = _connection;
            _connection = null;
            spike = _spike;
            _spike = null;
        }

        // The spike probes the connection, so stop it before disposing what it probes.
        spike?.Dispose();
        connection?.Dispose();
    }

    /// <summary>
    /// Drops everything from a previous activation.
    /// </summary>
    private void ResetState()
    {
        CloseSession();

        IOuterTransport? transport;
        Timer? watchdog;

        lock (_stateGate)
        {
            transport = _transport;
            _transport = null;
            _inbound = null;
            watchdog = _stopWatchdog;
            _stopWatchdog = null;
        }

        watchdog?.Dispose();
        transport?.Dispose();

        Volatile.Write(ref _decapsulateCalls, 0);
    }

    /// <summary>
    /// Stops the channel, once.
    /// </summary>
    private void StopChannel(VpnChannel? channel, string reason)
    {
        if (channel is null || Interlocked.Exchange(ref _channelStopped, 1) != 0)
        {
            return;
        }

        try
        {
            channel.Stop();
            PluginLog.Info($"Channel stopped: {reason}");
        }
        catch (Exception ex)
        {
            PluginLog.Error($"Stopping the channel failed ({reason})", ex);
        }

        ResetState();
    }

    /// <summary>
    /// Watches for the last decapsulate call that <see cref="Disconnect"/> asked for.
    /// </summary>
    /// <remarks>
    /// If it never comes, the channel is left running rather than stopped behind the platform's
    /// back: buffers we have not returned are precisely what makes <see cref="VpnChannel.Stop"/>
    /// dangerous, so stopping anyway would trade a stall for a killed host process. The queue state
    /// is logged either way, because which branch happens is a fact about the platform worth having.
    /// </remarks>
    private void ArmStopWatchdog(VpnChannel channel)
    {
        var watchdog = new Timer(
            static state =>
            {
                var (plugin, watched) = ((SSHVpnPlugin, VpnChannel))state!;
                plugin.OnStopWatchdog(watched);
            },
            (this, channel),
            StopWatchdogDelay,
            Timeout.InfiniteTimeSpan);

        Timer? previous;
        lock (_stateGate)
        {
            previous = _stopWatchdog;
            _stopWatchdog = watchdog;
        }

        previous?.Dispose();
    }

    private void OnStopWatchdog(VpnChannel channel)
    {
        if (Volatile.Read(ref _channelStopped) != 0)
        {
            return;
        }

        var inbound = GetInbound();
        if (inbound is null || inbound.IsFinished)
        {
            // Nothing of the platform's is still in our hands, so stopping is safe even though the
            // platform never came back to us.
            PluginLog.Error(
                "The platform did not call Decapsulate again after Disconnect; stopping the channel " +
                "directly, which is safe only because the inbound queue is empty.");
            StopChannel(channel, "watchdog, queue empty");
            return;
        }

        PluginLog.Error(
            "The platform did not call Decapsulate again after Disconnect and the inbound queue " +
            "still holds platform buffers. Not stopping the channel: returning those buffers is the " +
            "precondition for stopping, and stopping without them risks the host process.");
    }

    /// <summary>
    /// Builds the route assignment.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A literal <c>0.0.0.0/0</c> is never used, even though it is what "send everything" means. It
    /// is recorded in the reference implementation that a default route written that way pulls
    /// traffic back into the tunnel even from a socket bound to another interface, which would take
    /// the SSH session down with it. The split default covers exactly the same addresses and behaves.
    /// </para>
    /// <para>
    /// Only IPv4 routes are added, because only an IPv4 address is assigned: the platform hangs when
    /// given routes for a family it has no address for. The consequence is that IPv6 traffic keeps
    /// using the physical interface — it leaves the tunnel rather than being blocked.
    /// </para>
    /// </remarks>
    private static VpnRouteAssignment BuildRouteAssignment(SshVpnConfiguration configuration)
    {
        var assignment = new VpnRouteAssignment { ExcludeLocalSubnets = true };

        if (configuration.InclusionRoutes.Count == 0)
        {
            assignment.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("0.0.0.0"), 1));
            assignment.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("128.0.0.0"), 1));

            // Deliberately no IPv6 routes, even though an IPv6 address has to be assigned for Start
            // to succeed at all. There is no IPv6 stack behind this tunnel, so routing IPv6 into it
            // would black-hole it; leaving it unrouted keeps it on the physical interface. That is a
            // leak, and an accepted one until the stack grows an IPv6 path.
            if (configuration.RouteIPv6)
            {
                assignment.Ipv6InclusionRoutes.Add(new VpnRoute(new HostName("::"), 1));
                assignment.Ipv6InclusionRoutes.Add(new VpnRoute(new HostName("8000::"), 1));
            }
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

        // "." is the catch-all suffix: resolve every name through these servers. Note that this
        // takes effect the moment the channel starts, so until DNS is actually carried, a connected
        // tunnel means the machine cannot resolve names at all.
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
