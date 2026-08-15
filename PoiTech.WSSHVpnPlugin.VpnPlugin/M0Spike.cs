using System;
using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Threading;
using Windows.Networking.Vpn;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Answers the questions the reworked transport rests on, none of which is documented.
/// </summary>
/// <remarks>
/// <para>
/// <b>(1) Does the platform accept a loopback dummy as its outer tunnel transport?</b> That the
/// channel starts at all is the first result; everything below depends on it.
/// </para>
/// <para>
/// <b>(2) Does the doorbell injection path work?</b> A packet is written into a platform buffer on
/// this thread, queued, and the loopback socket rung; the platform should call
/// <c>Decapsulate</c>, which hands the buffer back. Success is not the call returning — it is the
/// echo request coming back out through <c>Encapsulate</c>, which proves inject, OS, and capture
/// all the way round. This is the path the packet path will actually use, which is why it is tested
/// in preference to the older one below.
/// </para>
/// <para>
/// <b>(3) Does SSH survive the channel starting?</b> The dangerous outcome was never rejection —
/// that is obvious — but acceptance followed by the platform reading our socket, which steals bytes
/// from the session's message loop and kills it minutes later. Now that SSH has a socket of its own
/// this should hold, so the probe keeps running well past where such a failure would appear.
/// </para>
/// <para>
/// <b>(4) What does the platform actually send us?</b> Reconnaissance for the filtering the stack
/// will need once a default route points at the tunnel.
/// </para>
/// <para>
/// Last and separately, whether the receive-buffer APIs may be called off the platform's thread.
/// That one only decides whether the doorbell can eventually be deleted, and it is the probe most
/// likely to wedge, so it runs after everything else has had its say.
/// </para>
/// <para>
/// Enable with <c>&lt;SpikeProbe&gt;true&lt;/SpikeProbe&gt;</c> in the profile's custom configuration.
/// This whole type is scaffolding and should be deleted once the answers are in.
/// </para>
/// </remarks>
internal sealed class M0Spike : IDisposable
{
    private static readonly TimeSpan ProbeInterval = TimeSpan.FromSeconds(20);

    /// <summary>
    /// How many liveness rounds to run before the probe that might wedge.
    /// </summary>
    private const int RoundsBeforeLegacyProbe = 2;

    /// <summary>A TEST-NET-1 address (RFC 5737), so the probe cannot be confused with real traffic.</summary>
    private static readonly byte[] ProbeSource = new byte[] { 192, 0, 2, 1 };

    private readonly VpnChannel _channel;
    private readonly SshVpnConnection _connection;
    private readonly InboundPacketQueue _inbound;
    private readonly IOuterTransport _transport;
    private readonly byte[] _clientAddress;
    private readonly CancellationTokenSource _stopping = new();
    private readonly Thread _thread;

    private int _packetsSampled;

    private M0Spike(
        VpnChannel channel,
        SshVpnConnection connection,
        InboundPacketQueue inbound,
        IOuterTransport transport,
        byte[] clientAddress)
    {
        _channel = channel;
        _connection = connection;
        _inbound = inbound;
        _transport = transport;
        _clientAddress = clientAddress;

        _thread = new Thread(Run)
        {
            IsBackground = true,
            Name = "wsshvpn-m0-spike",
        };
    }

    /// <summary>
    /// Starts the spike, or returns <see langword="null"/> if the client address is unusable.
    /// </summary>
    public static M0Spike? Start(
        VpnChannel channel,
        SshVpnConnection connection,
        InboundPacketQueue inbound,
        IOuterTransport transport,
        string clientIPv4)
    {
        if (!IPAddress.TryParse(clientIPv4, out var address)
            || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            PluginLog.Error($"M0 spike not started: '{clientIPv4}' is not an IPv4 address");
            return null;
        }

        var spike = new M0Spike(channel, connection, inbound, transport, address.GetAddressBytes());
        spike._thread.Start();
        return spike;
    }

    /// <summary>
    /// Logs a one-line summary of an outbound packet, up to a fixed budget.
    /// </summary>
    /// <remarks>
    /// Doubles as reconnaissance: it shows what Windows actually sends once a default route points
    /// at the tunnel, which decides how much of M2 is spent filtering noise. Bounded because
    /// <see cref="SSHVpnPlugin.Encapsulate"/> runs at line rate.
    /// </remarks>
    public void SampleOutbound(ReadOnlySpan<byte> packet)
    {
        const int SampleBudget = 40;

        if (Interlocked.Increment(ref _packetsSampled) > SampleBudget)
        {
            return;
        }

        PluginLog.Info($"outbound: {Describe(packet)}");
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _stopping.Cancel();
        _ = _thread.Join(TimeSpan.FromSeconds(2));
        _stopping.Dispose();
    }

    private void Run()
    {
        try
        {
            ProbeDoorbellInjection();

            var round = 0;
            while (!_stopping.Token.WaitHandle.WaitOne(ProbeInterval))
            {
                ProbeSshLiveness(++round);

                // Deliberately last: this is the probe that might not return, and by now every
                // other question has been answered in the log.
                if (round == RoundsBeforeLegacyProbe)
                {
                    ProbeWorkerThreadInjection();
                }
            }
        }
        catch (Exception ex)
        {
            PluginLog.Error("M0 spike thread failed", ex);
        }
    }

    /// <summary>
    /// (2) Injects one ICMP echo request the way the packet path will: a platform buffer filled on
    /// this thread, queued, and handed back inside the decapsulate call the doorbell provokes.
    /// </summary>
    /// <remarks>
    /// Sent from a fake source so that if Windows answers it, the reply arrives back through
    /// <see cref="SSHVpnPlugin.Encapsulate"/> addressed to TEST-NET-1 — which proves the whole
    /// inject-to-stack-and-back loop, not merely that the calls returned without throwing.
    /// </remarks>
    private void ProbeDoorbellInjection()
    {
        try
        {
            if (!_inbound.TryAcquire(out var buffer))
            {
                PluginLog.Error(
                    "M0'(2): the platform would not lend a receive buffer on this thread, so the " +
                    "doorbell path cannot be tested. The queue would have to carry copies instead.");
                return;
            }

            var span = VpnPacketBufferAccess.GetSpan(buffer.Buffer);
            var length = WriteIcmpEchoRequest(span, ProbeSource, _clientAddress);
            buffer.Buffer.Length = (uint)length;

            _inbound.Enqueue(buffer);
            _transport.RingDoorbell();

            PluginLog.Info(
                $"M0'(2): queued a {length}-byte ICMP echo request and rang the doorbell. A " +
                "'Decapsulate called' line means the platform answered; an 'outbound: ICMP 192.0.2.1' " +
                "line means the whole round trip worked.");
        }
        catch (Exception ex)
        {
            PluginLog.Error("M0'(2): the doorbell injection path FAILED", ex);
        }
    }

    /// <summary>
    /// Whether the receive-buffer APIs can be driven straight from a worker thread, skipping the
    /// queue and the doorbell entirely.
    /// </summary>
    /// <remarks>
    /// Only an optimisation if it works, so it runs last: it is the call most likely to wedge or
    /// take the host process down, and losing the earlier answers to it would be a wasted
    /// activation. The channel is single-shot, so there is no second attempt.
    /// </remarks>
    private void ProbeWorkerThreadInjection()
    {
        try
        {
            _channel.RequestVpnPacketBuffer(VpnDataPathType.Receive, out var buffer);

            var span = VpnPacketBufferAccess.GetSpan(buffer.Buffer);
            var length = WriteIcmpEchoRequest(span, ProbeSource, _clientAddress);
            buffer.Buffer.Length = (uint)length;

            _channel.AppendVpnReceivePacketBuffer(buffer);
            _channel.FlushVpnReceivePacketBuffers();

            PluginLog.Info(
                $"M0'(5): appended a {length}-byte ICMP echo request from a worker thread without " +
                "the doorbell. A second 'outbound: ICMP 192.0.2.1' line means the doorbell is " +
                "unnecessary and can be deleted.");
        }
        catch (Exception ex)
        {
            PluginLog.Error("M0'(5): injecting from a worker thread without the doorbell FAILED", ex);
        }
    }

    /// <summary>
    /// (3) Proves the SSH session still works after the channel started.
    /// </summary>
    private void ProbeSshLiveness(int round)
    {
        if (_connection.TryProbe(out var detail))
        {
            PluginLog.Info($"M0'(3): SSH still alive after channel start (round {round}): {detail}");
            return;
        }

        PluginLog.Error(
            $"M0'(3): SSH round trip FAILED at round {round} ({detail}). If earlier rounds passed, " +
            "something else is reading the socket the session runs on.");
    }

    private static string Describe(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 20 || (packet[0] >> 4) != 4)
        {
            return string.Format(CultureInfo.InvariantCulture, "non-IPv4 or truncated, {0} bytes", packet.Length);
        }

        var protocol = packet[9] switch
        {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            var other => other.ToString(CultureInfo.InvariantCulture),
        };

        var source = new IPAddress(packet.Slice(12, 4).ToArray());
        var destination = new IPAddress(packet.Slice(16, 4).ToArray());
        var ports = string.Empty;

        var headerLength = (packet[0] & 0x0F) * 4;
        if ((packet[9] is 6 or 17) && packet.Length >= headerLength + 4)
        {
            var sourcePort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(headerLength, 2));
            var destinationPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(headerLength + 2, 2));
            ports = string.Format(CultureInfo.InvariantCulture, " {0}->{1}", sourcePort, destinationPort);
        }

        return string.Format(
            CultureInfo.InvariantCulture,
            "{0} {1} -> {2}{3}, {4} bytes",
            protocol,
            source,
            destination,
            ports,
            packet.Length);
    }

    /// <summary>
    /// Writes an IPv4 ICMP echo request, and returns its total length.
    /// </summary>
    private static int WriteIcmpEchoRequest(Span<byte> destination, ReadOnlySpan<byte> source, ReadOnlySpan<byte> target)
    {
        const int IPv4HeaderLength = 20;
        const int IcmpHeaderLength = 8;
        const int PayloadLength = 8;

        var total = IPv4HeaderLength + IcmpHeaderLength + PayloadLength;
        if (destination.Length < total)
        {
            throw new InvalidOperationException(
                $"The receive buffer holds {destination.Length} bytes; the probe needs {total}.");
        }

        var packet = destination.Slice(0, total);
        packet.Clear();

        packet[0] = 0x45;                                                            // IPv4, 20-byte header
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(2, 2), (ushort)total);    // total length
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(4, 2), 0xB0B0);           // identification
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(6, 2), 0x4000);           // don't fragment
        packet[8] = 64;                                                              // TTL
        packet[9] = 1;                                                               // ICMP
        source.CopyTo(packet.Slice(12, 4));
        target.CopyTo(packet.Slice(16, 4));
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(10, 2), Checksum(packet.Slice(0, IPv4HeaderLength)));

        var icmp = packet.Slice(IPv4HeaderLength);
        icmp[0] = 8;                                                                 // echo request
        BinaryPrimitives.WriteUInt16BigEndian(icmp.Slice(4, 2), 0xB0B0);             // identifier
        BinaryPrimitives.WriteUInt16BigEndian(icmp.Slice(6, 2), 1);                  // sequence
        BinaryPrimitives.WriteUInt16BigEndian(icmp.Slice(2, 2), Checksum(icmp));

        return total;
    }

    /// <summary>
    /// The internet checksum (RFC 1071): the one's complement of the one's complement sum.
    /// </summary>
    private static ushort Checksum(ReadOnlySpan<byte> data)
    {
        uint sum = 0;

        while (data.Length > 1)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(data);
            data = data.Slice(2);
        }

        if (data.Length == 1)
        {
            sum += (uint)(data[0] << 8);
        }

        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)~sum;
    }
}
