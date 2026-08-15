using System;
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
    private readonly Dictionary<TcpFlowKey, TcpFlow> _flows = new();
    private readonly List<TcpFlowKey> _finished = new();

    public StackLoop(IByteChannelFactory channels, IPacketSink sink)
    {
        _channels = channels;
        _sink = sink;
    }

    /// <summary>Gets the number of flows currently tracked.</summary>
    public int FlowCount => _flows.Count;

    /// <summary>Gets the number of packets dropped as uninteresting.</summary>
    public long Dropped { get; private set; }

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
        if (ip.IsFragment || !IsUnicast(ip.Destination) || ip.Protocol != IpProtocol.Tcp)
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
            flow = new TcpFlow(key, _sink);
            _flows[key] = flow;
        }

        var wantsChannel = flow.Accept(tcp);

        if (wantsChannel)
        {
            var pending = flow;
            _channels.BeginOpen(
                key.RemoteAddress,
                key.RemotePort,
                channel => pending.OnChannelOpened(channel),
                pending.OnChannelFailed);
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
