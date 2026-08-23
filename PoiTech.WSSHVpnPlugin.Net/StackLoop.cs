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

    /// <summary>The tunnel MTU, from which every flow derives its segment size and scratch.</summary>
    private readonly int _mtu;
    private readonly Dictionary<TcpFlowKey, TcpFlow> _flows = new();
    private readonly List<TcpFlowKey> _finished = new();

    /// <summary>Retransmissions carried out by flows that have since been forgotten.</summary>
    private long _retiredRetransmissions;
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

    public StackLoop(IByteChannelFactory channels, IPacketSink sink, IStackClock clock, int mtu)
    {
        _channels = channels;
        _sink = sink;
        _clock = clock;
        _mtu = mtu;
        _dns = new DnsRelay(sink, clock, OpenChannel, mtu);
    }

    /// <summary>Gets the number of flows currently tracked.</summary>
    public int FlowCount => _flows.Count;

    /// <summary>Gets the number of packets dropped as uninteresting.</summary>
    public long Dropped { get; private set; }

    /// <summary>Gets the number of IPv6 packets dropped, separately from the v4 noise.</summary>
    /// <remarks>
    /// Separate because it answers a different question. The v4 counter absorbs known chatter -
    /// SSDP, LLMNR, NetBIOS - while this one is the first thing to read when IPv6 through the
    /// tunnel misbehaves: a working v6 path drops little, and a broken one shows exactly what is
    /// being refused, with <see cref="DescribeIcmpV6"/> saying what the platform was asking for.
    /// </remarks>
    public long DroppedV6 { get; private set; }

    /// <summary>
    /// Called once per ICMPv6 type the tunnel sees, with the type, code and addresses of the first
    /// occurrence.
    /// </summary>
    /// <remarks>
    /// ICMPv6 is not carried, but what arrives is evidence: whether Windows expects Neighbour
    /// Discovery to be answered on this interface is not written down anywhere, so the first
    /// connect with v6 routed in answers it by observation. Once per type, so a flood costs one
    /// log line.
    /// </remarks>
    public Action<byte, byte, IpAddr, IpAddr>? IcmpV6Seen { get; set; }

    /// <summary>Counts of ICMPv6 packets by type, allocated the first time one arrives.</summary>
    private long[]? _icmpV6Types;

    /// <summary>Gets how the DNS relay has been faring, for the host to report.</summary>
    public (long Answered, long Truncated, long Dropped, int Channels) DnsCounters =>
        (_dns.Answered, _dns.Truncated, _dns.Dropped, _dns.Channels);

    /// <summary>
    /// Releases what the stack holds. Call only once whatever drives <see cref="RunOnce"/> has
    /// stopped.
    /// </summary>
    public void Dispose()
    {
        _dns.Dispose();

        foreach (var flow in _flows.Values)
        {
            flow.Abort();
        }

        _flows.Clear();
    }

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
    /// Called when the peer resets a flow the stack still holds, with the sender's post-mortem.
    /// </summary>
    /// <remarks>
    /// A reset from the peer is the application on the other side giving up, and it is the only
    /// visible symptom of a flow that wedged: everything else about a wedge is silence. The
    /// description says what the sender looked like at that moment - see
    /// <see cref="TcpFlow.Describe"/>.
    /// </remarks>
    public Action<TcpFlowKey, string>? FlowReset { get; set; }

    /// <summary>
    /// Gets how many times a retransmission timeout has fired across every flow, living and dead.
    /// </summary>
    public long Retransmissions
    {
        get
        {
            var total = _retiredRetransmissions;

            foreach (var flow in _flows.Values)
            {
                total += flow.Retransmissions;
            }

            return total;
        }
    }

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
        if (Ipv4Packet.TryParse(packet, out var ip))
        {
            // Dropped before the flow table is touched. A default route through the tunnel drags in
            // SSDP, LLMNR, mDNS, NetBIOS and NCSI probes, and hashing a four-tuple for each of them
            // would be work done purely to throw the result away.
            if (ip.IsFragment || !IsUnicast(ip.Destination))
            {
                Dropped++;
                return false;
            }

            return Demultiplex(IpAddr.FromV4(ip.Source), IpAddr.FromV4(ip.Destination), ip.Protocol, ip.Payload);
        }

        if (Ipv6Packet.TryParse(packet, out var ip6))
        {
            return OfferV6(ip6);
        }

        Dropped++;
        return false;
    }

    /// <summary>
    /// Takes an IPv6 packet: transports go to the shared demultiplexer, everything else is counted
    /// and dropped.
    /// </summary>
    /// <remarks>
    /// Extension headers are not walked - a next header that is not directly a transport is
    /// dropped. Host-originated traffic puts TCP and UDP straight after the fixed header, so the
    /// walk would run zero times on everything this stack serves; a fragment header gets the same
    /// treatment as a v4 fragment for the same reason.
    /// </remarks>
    private bool OfferV6(Ipv6Packet ip)
    {
        // Recorded before the unicast filter, deliberately: Neighbour Solicitations go to
        // solicited-node multicast, so filtering multicast first would blind the one histogram the
        // first v6 deploy exists to read.
        if (ip.NextHeader == IpProtocol.IcmpV6)
        {
            RecordIcmpV6(ip);
            DroppedV6++;
            return false;
        }

        if (ip.NextHeader is not (IpProtocol.Tcp or IpProtocol.Udp))
        {
            DroppedV6++;
            return false;
        }

        var destination = ip.Destination;

        if (!IsUnicastV6(destination))
        {
            DroppedV6++;
            return false;
        }

        return Demultiplex(ip.Source, destination, ip.NextHeader, ip.Payload);
    }

    /// <summary>
    /// Dispatches one unicast transport payload, of either family, onto a flow or the DNS relay.
    /// </summary>
    private bool Demultiplex(IpAddr source, IpAddr destination, IpProtocol protocol, Span<byte> payload)
    {
        // The one exception to "TCP only". Name resolution for the whole machine is pinned to the
        // tunnel the moment it starts, so UDP/53 going nowhere does not degrade gracefully - it
        // breaks every name on the system.
        if (protocol == IpProtocol.Udp)
        {
            if (UdpDatagram.TryParse(payload, out var udp) && udp.DestinationPort == DnsRelay.Port)
            {
                return _dns.Offer(source, destination, udp);
            }

            Drop(source);
            return false;
        }

        if (protocol != IpProtocol.Tcp)
        {
            Drop(source);
            return false;
        }

        if (!TcpSegment.TryParse(payload, out var tcp))
        {
            Drop(source);
            return false;
        }

        var key = new TcpFlowKey(source, tcp.SourcePort, destination, tcp.DestinationPort);

        if (!_flows.TryGetValue(key, out var flow))
        {
            if ((tcp.Flags & TcpFlags.Rst) != 0)
            {
                // A reset for a connection nothing holds answers nothing: replying to a reset is
                // how two stacks chase each other in circles.
                Dropped++;
                return false;
            }

            if ((tcp.Flags & TcpFlags.Syn) == 0)
            {
                // The in-flight stragglers of a connection whose flow is already gone, which arrive
                // in a burst when a peer gives up. Each gets its reset without a flow being created
                // to send it, so the flow-started log stays a log of connections.
                TcpFlow.Reset(_sink, key, tcp);
                return true;
            }

            flow = new TcpFlow(key, _sink, _clock, _mtu);
            _flows[key] = flow;
            FlowStarted?.Invoke(key);
        }
        else if ((tcp.Flags & TcpFlags.Rst) != 0)
        {
            // Described before Accept aborts it, while the sender's state still exists.
            FlowReset?.Invoke(key, flow.Describe());
        }

        var wantsChannel = flow.Accept(tcp);

        if (wantsChannel)
        {
            var pending = flow;
            OpenChannel(key.RemoteAddress, key.RemotePort, pending.OnChannelOpened, pending.OnChannelFailed);
        }

        if (flow.IsFinished)
        {
            _retiredRetransmissions += flow.Retransmissions;
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
                _retiredRetransmissions += pair.Value.Retransmissions;
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
    private void OpenChannel(IpAddr address, ushort port, Action<IByteChannel> onOpened, Action onFailed)
    {
        // The reason stops here: a flow answers every failure the same way (a refusal to the
        // peer), so only the factory layers below - the negative cache among them - care why.
        _channels.BeginOpen(
            address,
            port,
            channel => _arrivals.Enqueue(() => onOpened(channel)),
            _ => _arrivals.Enqueue(onFailed));
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

    /// <summary>
    /// Determines whether an IPv6 destination is one worth opening a connection to.
    /// </summary>
    /// <remarks>
    /// Excludes the unspecified address, multicast (<c>ff00::/8</c>, which absorbs the router and
    /// neighbour solicitation, MLD and LLMNR noise a default-routed tunnel attracts), and
    /// link-local (<c>fe80::/10</c>) - a stream to a link-local address is meaningless from the SSH
    /// server's side of the tunnel.
    /// </remarks>
    private static bool IsUnicastV6(in IpAddr address)
    {
        if (address.High == 0 && address.Low == 0)
        {
            return false;
        }

        if ((address.High >> 56) == 0xFF)
        {
            return false;
        }

        return (address.High >> 54) != 0x3FA;
    }

    /// <summary>Counts a drop against the family of the packet that carried it.</summary>
    private void Drop(in IpAddr source)
    {
        if (source.IsV4)
        {
            Dropped++;
        }
        else
        {
            DroppedV6++;
        }
    }

    private void RecordIcmpV6(in Ipv6Packet ip)
    {
        var payload = ip.Payload;

        if (payload.Length < 4)
        {
            return;
        }

        _icmpV6Types ??= new long[256];

        var type = payload[0];

        if (_icmpV6Types[type]++ == 0)
        {
            IcmpV6Seen?.Invoke(type, payload[1], ip.Source, ip.Destination);
        }
    }

    /// <summary>
    /// Describes the ICMPv6 seen so far, as <c>type:count</c> pairs, or an empty string when none
    /// has arrived.
    /// </summary>
    public string DescribeIcmpV6()
    {
        if (_icmpV6Types is null)
        {
            return string.Empty;
        }

        var parts = new List<string>();

        for (var type = 0; type < _icmpV6Types.Length; type++)
        {
            if (_icmpV6Types[type] > 0)
            {
                parts.Add($"{type}:{_icmpV6Types[type]}");
            }
        }

        return string.Join(" ", parts);
    }
}
