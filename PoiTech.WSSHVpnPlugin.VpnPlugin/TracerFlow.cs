using System;
using System.Threading;
using System.Threading.Tasks;
using PoiTech.WSSHVpnPlugin.Net;
using Renci.SshNet;
using Renci.SshNet.Channels;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Carries exactly one TCP connection over a <c>direct-tcpip</c> channel.
/// </summary>
/// <remarks>
/// <para>
/// The tracer bullet for the packet path, and deliberately the least impressive thing that can work:
/// one flow, no timers, no retransmission, no out-of-order handling, no backpressure beyond what the
/// SSH window imposes, and no second connection. It exists to prove the parts that unit tests cannot
/// reach — the platform hands us packets, the stack answers them, the SSH channel carries the bytes,
/// and the replies get back in through the doorbell — before the properly testable TCP logic is
/// built out on top.
/// </para>
/// <para>
/// Everything a real implementation needs and this does not have is listed in the plan under M2.
/// The gaps that would matter first: a lost segment is lost for good, a second connection is
/// refused, and data arriving out of order is dropped rather than reassembled.
/// </para>
/// </remarks>
internal sealed class TracerFlow : IDisposable
{
    /// <summary>Our MTU less the IPv4 and TCP headers.</summary>
    private const ushort OurMaximumSegmentSize = 1360;

    /// <summary>What we advertise as our receive window. Fixed, because nothing here varies it.</summary>
    private const ushort OurWindow = 65535;

    private readonly SshClient _client;
    private readonly InboundPacketQueue _inbound;
    private readonly IOuterTransport _transport;
    private readonly object _gate = new();

    private uint _clientAddress;
    private uint _serverAddress;
    private ushort _clientPort;
    private ushort _serverPort;

    private DirectTcpipStream? _stream;
    private uint _sendNext;
    private uint _recvNext;
    private bool _claimed;
    private bool _established;
    private bool _finished;
    private int _disposed;

    private readonly uint _targetAddress;
    private readonly ushort _targetPort;

    public TracerFlow(SshClient client, InboundPacketQueue inbound, IOuterTransport transport, uint targetAddress, ushort targetPort)
    {
        _client = client;
        _inbound = inbound;
        _transport = transport;
        _targetAddress = targetAddress;
        _targetPort = targetPort;
    }

    /// <summary>
    /// Offers an outbound packet to the flow.
    /// </summary>
    /// <param name="packet">The IP packet the platform handed us.</param>
    /// <returns>
    /// <see langword="true"/> if the packet belonged to this flow and was handled; otherwise,
    /// <see langword="false"/>, and the caller should drop it.
    /// </returns>
    /// <remarks>
    /// Runs on the platform's thread, so it must not block. Opening the SSH channel is a round trip
    /// and therefore happens on a worker; the handshake is completed from there.
    /// </remarks>
    public bool TryHandle(Span<byte> packet)
    {
        if (!Ipv4Packet.TryParse(packet, out var ip) || ip.Protocol != IpProtocol.Tcp || ip.IsFragment)
        {
            return false;
        }

        if (!TcpSegment.TryParse(ip.Payload, out var tcp))
        {
            return false;
        }

        // Copied out before anything can block or await: the views point into the platform's buffer,
        // which it takes back the moment we return.
        var source = ip.Source;
        var destination = ip.Destination;
        var sourcePort = tcp.SourcePort;
        var destinationPort = tcp.DestinationPort;
        var flags = tcp.Flags;
        var sequenceNumber = tcp.SequenceNumber;
        var payload = tcp.Payload.ToArray();
        var hasMss = tcp.TryGetMaximumSegmentSize(out _);

        lock (_gate)
        {
            if (!_claimed)
            {
                if ((flags & TcpFlags.Syn) == 0 || (flags & TcpFlags.Ack) != 0)
                {
                    // Only a fresh connection attempt starts this flow.
                    return false;
                }

                if (destination != _targetAddress || destinationPort != _targetPort)
                {
                    // Anything else is background traffic. A Windows machine opens plenty of
                    // connections unprompted, and with one flow to give away, first-come is useless.
                    return false;
                }

                _claimed = true;
                _clientAddress = source;
                _serverAddress = destination;
                _clientPort = sourcePort;
                _serverPort = destinationPort;
                _recvNext = sequenceNumber + 1;      // the SYN occupies one sequence number
                _sendNext = 0;                       // our ISN; zero is fine for a tracer

                PluginLog.Info(
                    $"tracer: adopting {Ipv4Packet.Format(source)}:{sourcePort} -> " +
                    $"{Ipv4Packet.Format(destination)}:{destinationPort} (peer sent MSS: {hasMss})");

                _ = Task.Run(OpenChannelAsync);
                return true;
            }

            if (source != _clientAddress || destination != _serverAddress ||
                sourcePort != _clientPort || destinationPort != _serverPort)
            {
                // One flow only. A second connection is dropped rather than mishandled.
                return false;
            }

            if ((flags & TcpFlags.Rst) != 0)
            {
                PluginLog.Info("tracer: client reset the connection");
                Close();
                return true;
            }

            if (!_established)
            {
                // Still waiting for the channel; the client's retransmitted SYN needs no answer yet.
                return true;
            }

            if (payload.Length > 0)
            {
                if (sequenceNumber != _recvNext)
                {
                    // Out of order. Dropping it and re-acknowledging what we do have makes the peer
                    // retransmit; reassembly is M2's problem.
                    PluginLog.Info($"tracer: dropping out-of-order segment (expected {_recvNext}, got {sequenceNumber})");
                    SendControl(TcpFlags.Ack);
                    return true;
                }

                SendToChannel(payload);
                _recvNext += (uint)payload.Length;
                SendControl(TcpFlags.Ack);
            }

            if ((flags & TcpFlags.Fin) != 0)
            {
                _recvNext++;
                PluginLog.Info("tracer: client finished sending");
                SendControl(TcpFlags.Ack);
                _stream?.SendEof();
            }

            return true;
        }
    }

    private async Task OpenChannelAsync()
    {
        try
        {
            var host = Ipv4Packet.Format(_serverAddress);
            var stream = await Task.Run(() => _client.CreateDirectTcpipStream(host, _serverPort)).ConfigureAwait(false);

            lock (_gate)
            {
                _stream = stream;
                _established = true;
            }

            stream.DataAvailable += OnChannelData;
            stream.PeerEof += OnChannelEof;
            stream.PeerClosed += OnChannelClosed;

            PluginLog.Info($"tracer: channel open to {host}:{_serverPort}, answering the handshake");

            lock (_gate)
            {
                // SYN-ACK carries our MSS. Omitting it leaves the peer assuming 536 and everything
                // then works at half throughput with nothing to show for it.
                SendControl(TcpFlags.Syn | TcpFlags.Ack, OurMaximumSegmentSize);
                _sendNext++;   // our SYN occupies a sequence number
            }

            // Anything that arrived before the handlers were attached.
            OnChannelData(stream, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            PluginLog.Error("tracer: could not open the channel; resetting the connection", ex);

            lock (_gate)
            {
                SendControl(TcpFlags.Rst | TcpFlags.Ack);
                _claimed = false;
            }
        }
    }

    /// <summary>
    /// Sends what the SSH window accepts. Anything it refuses is dropped, which for a tracer means
    /// the connection stalls - there is no retransmission to recover it.
    /// </summary>
    private void SendToChannel(byte[] payload)
    {
        var stream = _stream;
        if (stream is null)
        {
            return;
        }

        var result = stream.TrySend(payload, 0, payload.Length, out var written);

        if (result != ChannelSendResult.Written)
        {
            PluginLog.Error($"tracer: channel took {written} of {payload.Length} bytes ({result}); the flow will stall");
        }
    }

    private void OnChannelData(object? sender, EventArgs e)
    {
        var stream = _stream;
        if (stream is null)
        {
            return;
        }

        while (stream.TryRead(out var data))
        {
            var take = Math.Min(data.Count, OurMaximumSegmentSize);

            lock (_gate)
            {
                if (!Inject(TcpFlags.Ack | TcpFlags.Psh, data.Array!, data.Offset, take))
                {
                    // No platform buffer to hand back; leave the bytes unreleased so the SSH window
                    // closes and the far end stops sending.
                    return;
                }

                _sendNext += (uint)take;
            }

            if (stream.Advance(take))
            {
                stream.FlushWindowCredit();
            }
        }
    }

    private void OnChannelEof(object? sender, EventArgs e)
    {
        lock (_gate)
        {
            if (_finished)
            {
                return;
            }

            _finished = true;
            PluginLog.Info("tracer: remote finished sending; sending FIN");
            SendControl(TcpFlags.Fin | TcpFlags.Ack);
            _sendNext++;
        }
    }

    private void OnChannelClosed(object? sender, EventArgs e)
    {
        PluginLog.Info("tracer: channel closed");
    }

    private void SendControl(TcpFlags flags, ushort? mss = null)
    {
        _ = Inject(flags, Array.Empty<byte>(), 0, 0, mss);
    }

    /// <summary>
    /// Builds a segment addressed back at the client and queues it for the platform.
    /// </summary>
    private bool Inject(TcpFlags flags, byte[] payload, int offset, int count, ushort? mss = null)
    {
        if (!_inbound.TryAcquire(out var buffer))
        {
            return false;
        }

        try
        {
            var span = VpnPacketBufferAccess.GetSpan(buffer);

            var tcpStart = Ipv4Packet.MinimumHeaderLength;
            var tcpHeaderLength = TcpSegment.MinimumHeaderLength + (mss.HasValue ? 4 : 0);

            if (count > 0)
            {
                payload.AsSpan(offset, count).CopyTo(span[(tcpStart + tcpHeaderLength)..]);
            }

            // Reversed: what the client sent to the server now comes from the server to the client.
            var tcpLength = TcpSegment.Write(
                span[tcpStart..],
                _serverAddress,
                _clientAddress,
                _serverPort,
                _clientPort,
                _sendNext,
                _recvNext,
                flags,
                OurWindow,
                count,
                mss);

            var total = Ipv4Packet.Write(span, IpProtocol.Tcp, _serverAddress, _clientAddress, tcpLength);
            buffer.Buffer.Length = (uint)total;

            _inbound.Enqueue(buffer);
            _transport.RingDoorbell();
            return true;
        }
        catch (Exception ex)
        {
            PluginLog.Error("tracer: failed to build a reply segment", ex);
            return false;
        }
    }

    private void Close()
    {
        var stream = _stream;
        _stream = null;
        _established = false;
        _claimed = false;

        stream?.Dispose();
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        lock (_gate)
        {
            Close();
        }
    }
}
