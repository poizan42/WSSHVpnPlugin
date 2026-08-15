using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// Demultiplexes packets onto flows, and drives them.
/// </summary>
/// <remarks>
/// <para>
/// Separate from whatever thread runs it. In production a dedicated thread calls
/// <see cref="Offer"/> and <see cref="RunOnce"/>; in tests they are called directly, which is what
/// makes the stack's behaviour observable without timing or threads.
/// </para>
/// <para>
/// Single-threaded by contract: the flow table and every TCB it holds are touched only from the
/// thread that drives the loop.
/// </para>
/// </remarks>
internal sealed class StackLoop
{
    private readonly IByteChannelFactory _channels;
    private readonly IPacketSink _sink;
    private readonly IStackClock _clock;
    private readonly Dictionary<TcpFlowKey, TcpFlow> _flows = new();
    private readonly List<TcpFlowKey> _finished = new();
    private readonly DnsRelay _dns;

    /// <summary>
    /// Work handed back by whoever opened a channel, waiting to run on the stack's own thread.
    /// </summary>
    /// <remarks>
    /// Opening a channel is a round trip, so the factory does it on a worker and calls back from
    /// there. Running that callback where it lands would touch a flow's state from a second thread,
    /// against everything <see cref="TcpFlow"/> assumes - two threads writing one flow's scratch
    /// buffer produce a corrupt packet, not an exception, which is the kind of fault that gets blamed
    /// on the peer for a week. So the callback only queues, and the queue drains here.
    /// </remarks>
    private readonly ConcurrentQueue<Action> _arrivals = new();

    public StackLoop(IByteChannelFactory channels, IPacketSink sink, IStackClock clock)
    {
        _channels = channels;
        _sink = sink;
        _clock = clock;
        _dns = new DnsRelay(sink, clock, OpenChannel);
    }

    /// <summary>Gets the number of flows currently tracked.</summary>
    public int FlowCount => _flows.Count;

    /// <summary>Gets the number of packets dropped as uninteresting.</summary>
    public long Dropped { get; private set; }

    /// <summary>Gets how the DNS relay has been faring, for the host to report.</summary>
    public (long Answered, long Truncated, long Dropped) DnsCounters =>
        (_dns.Answered, _dns.Truncated, _dns.Dropped);

    /// <summary>
    /// Called when a flow is first seen, with its four-tuple.
    /// </summary>
    /// <remarks>
    /// For the host to log. The stack does not know how the host logs, and a flow's whole tuple is
    /// the thing worth knowing when a connection turns up that should not have been routed here at
    /// all - the destination alone does not say which interface the operating system chose.
    /// </remarks>
    public Action<TcpFlowKey>? FlowStarted { get; set; }

    /// <summary>
    /// Offers an outbound packet to the stack.
    /// </summary>
    /// <param name="packet">The packet the operating system wants sent.</param>
    /// <returns>
    /// <see langword="true"/> if a flow took it; otherwise, <see langword="false"/> and it was
    /// dropped.
    /// </returns>
    public bool Offer(Span<byte> packet)
    {
        if (!Ipv4Packet.TryParse(packet, out var ip))
        {
            Dropped++;
            return false;
        }

        // Dropped before the flow table is touched. A default route through the tunnel drags in
        // SSDP, LLMNR, mDNS, NetBIOS and NCSI probes, and hashing a four-tuple for each of them
        // would be work done purely to throw the result away.
        if (ip.IsFragment || !IsUnicast(ip.Destination))
        {
            Dropped++;
            return false;
        }

        // The one exception to "TCP only". Name resolution for the whole machine is pinned to the
        // tunnel the moment it starts, so UDP/53 going nowhere does not degrade gracefully - it
        // breaks every name on the system.
        if (ip.Protocol == IpProtocol.Udp)
        {
            if (UdpDatagram.TryParse(ip.Payload, out var udp) && udp.DestinationPort == DnsRelay.Port)
            {
                return _dns.Offer(ip.Source, ip.Destination, udp);
            }

            Dropped++;
            return false;
        }

        if (ip.Protocol != IpProtocol.Tcp)
        {
            Dropped++;
            return false;
        }

        if (!TcpSegment.TryParse(ip.Payload, out var tcp))
        {
            Dropped++;
            return false;
        }

        var key = new TcpFlowKey(ip.Source, tcp.SourcePort, ip.Destination, tcp.DestinationPort);

        if (!_flows.TryGetValue(key, out var flow))
        {
            flow = new TcpFlow(key, _sink, _clock);
            _flows[key] = flow;
            FlowStarted?.Invoke(key);
        }

        var wantsChannel = flow.Accept(tcp);

        if (wantsChannel)
        {
            var pending = flow;
            OpenChannel(key.RemoteAddress, key.RemotePort, pending.OnChannelOpened, pending.OnChannelFailed);
        }

        if (flow.IsFinished)
        {
            _ = _flows.Remove(key);
        }

        return true;
    }

    /// <summary>
    /// Gives every flow a chance to move bytes inbound, and forgets the finished ones.
    /// </summary>
    /// <returns><see langword="true"/> if any flow made progress.</returns>
    public bool RunOnce()
    {
        var progressed = false;

        // Channels that finished opening while we were elsewhere. First, so a flow that has just
        // been given its channel gets pumped in this same pass rather than the next one.
        while (_arrivals.TryDequeue(out var arrival))
        {
            arrival();
            progressed = true;
        }

        if (_dns.RunOnce())
        {
            progressed = true;
        }

        foreach (var pair in _flows)
        {
            if (pair.Value.PumpInbound())
            {
                progressed = true;
            }

            if (pair.Value.IsFinished)
            {
                _finished.Add(pair.Key);
            }
        }

        foreach (var key in _finished)
        {
            _ = _flows.Remove(key);
        }

        _finished.Clear();
        return progressed;
    }

    /// <summary>
    /// Opens a channel, marshalling the answer back onto the stack's thread.
    /// </summary>
    private void OpenChannel(uint address, ushort port, Action<IByteChannel> onOpened, Action onFailed)
    {
        _channels.BeginOpen(
            address,
            port,
            channel => _arrivals.Enqueue(() => onOpened(channel)),
            () => _arrivals.Enqueue(onFailed));
    }

    /// <summary>
    /// Determines whether an address is one worth opening a connection to.
    /// </summary>
    /// <remarks>
    /// Excludes broadcast, multicast and the unspecified address. These arrive constantly on a
    /// tunnel holding the default route and none of them can be carried by a stream to a host.
    /// </remarks>
    private static bool IsUnicast(uint address)
    {
        if (address == 0 || address == 0xFFFFFFFF)
        {
            return false;
        }

        // 224.0.0.0/4
        return (address & 0xF0000000) != 0xE0000000;
    }
}
