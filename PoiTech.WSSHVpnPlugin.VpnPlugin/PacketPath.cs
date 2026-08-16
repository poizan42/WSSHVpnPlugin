using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using PoiTech.WSSHVpnPlugin.Net;
using Renci.SshNet;
using Windows.Networking.Vpn;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Runs the user-space TCP/IP stack, and owns the thread it runs on.
/// </summary>
/// <remarks>
/// <para>
/// The platform's thread hands packets in through <see cref="Offer"/> and returns immediately; the
/// stack's own thread does the work. That split is the whole concurrency model: the platform thread
/// must never wait on us, and the stack must never be entered from two threads at once, so it owns
/// its state without locking any of it.
/// </para>
/// <para>
/// A full inbound queue drops. The alternative is blocking the platform, which is how a plug-in gets
/// its host killed, and the operating system will retransmit anything dropped here - it is the same
/// mechanism that covers a lossy link.
/// </para>
/// </remarks>
internal sealed class PacketPath : IDisposable
{
    /// <summary>
    /// How many outbound packets may be waiting for the stack thread.
    /// </summary>
    /// <remarks>
    /// Deep enough to absorb a burst, shallow enough that a stalled stack sheds load rather than
    /// hoarding it. Every packet here is a copy the platform has already taken back.
    /// </remarks>
    private const int OutboundQueueCapacity = 256;

    /// <summary>
    /// How long the stack thread sleeps when it has nothing to do.
    /// </summary>
    /// <remarks>
    /// Bounded rather than infinite because delayed acknowledgements are due on a timer, and nothing
    /// wakes the thread when the only thing outstanding is the passage of time.
    /// </remarks>
    private static readonly TimeSpan IdleWait = TimeSpan.FromMilliseconds(20);

    /// <summary>
    /// How many passes may fail in a row before the thread gives up.
    /// </summary>
    private const int MaximumConsecutiveFailures = 10;

    /// <summary>
    /// How often the counters are written to the log.
    /// </summary>
    /// <remarks>
    /// Reported while running rather than only at shutdown. The host process does not always live
    /// long enough to tear down cleanly - a run can end with no summary at all - and a milestone that
    /// cannot be measured after the fact cannot be judged.
    /// </remarks>
    private static readonly TimeSpan ReportInterval = TimeSpan.FromSeconds(30);

    private readonly StackLoop _stack;
    private readonly InboundPacketSink _sink;
    private readonly SshByteChannelFactory _factory;
    private readonly RefusalCachingChannelFactory _refusals;
    private readonly Queue<byte[]> _outbound = new();
    private readonly object _gate = new();
    private readonly AutoResetEvent _wake = new(initialState: false);
    private readonly Thread _thread;

    private volatile bool _stopping;
    private int _disposed;
    private long _dropped;
    private long _lastReport = Environment.TickCount64;
    private long _lastRateAt = Environment.TickCount64;
    private long _lastIn;
    private long _lastOut;
    private long _lastReads;
    private long _lastReadBytes;
    private long _lastReadTicks;
    private long _lastAdjusts;
    private long _lastCredited;

    public PacketPath(SshClient client, InboundPacketQueue queue, IOuterTransport transport, TimeSpan openTimeout)
    {
        var clock = new MonotonicClock();

        _sink = new InboundPacketSink(queue, transport);
        _factory = new SshByteChannelFactory(client, Wake, openTimeout);

        // Between the stack and the real opens: destinations the server just refused are refused
        // again from memory, so a peer that retries steadily does not cost a round trip per retry.
        _refusals = new RefusalCachingChannelFactory(_factory, clock);
        _stack = new StackLoop(_refusals, _sink, clock)
        {
            FlowStarted = key => PluginLog.Info(
                $"flow {Ipv4Packet.Format(key.LocalAddress)}:{key.LocalPort} -> " +
                $"{Ipv4Packet.Format(key.RemoteAddress)}:{key.RemotePort}"),

            // The client resetting a live flow is its application giving up, and the sender's
            // post-mortem is the only evidence of why: a wedge is silent everywhere else.
            FlowReset = (key, description) => PluginLog.Info(
                $"flow {Ipv4Packet.Format(key.LocalAddress)}:{key.LocalPort} -> " +
                $"{Ipv4Packet.Format(key.RemoteAddress)}:{key.RemotePort} reset by the client — {description}"),
        };

        _thread = new Thread(Run)
        {
            IsBackground = true,
            Name = "wsshvpn-stack",
        };
    }

    /// <summary>Gets how many outbound packets were dropped because the queue was full.</summary>
    public long Dropped => Interlocked.Read(ref _dropped);

    /// <summary>Starts the stack thread.</summary>
    public void Start()
    {
        _thread.Start();
    }

    /// <summary>
    /// Takes a packet from the platform.
    /// </summary>
    /// <param name="packet">The packet, which the platform reclaims as soon as this returns.</param>
    /// <remarks>
    /// Copies, because the buffer belongs to the platform and goes back to it immediately. This is
    /// the one copy on the outbound path.
    /// </remarks>
    public void Offer(ReadOnlySpan<byte> packet)
    {
        var copy = packet.ToArray();

        lock (_gate)
        {
            if (_stopping)
            {
                return;
            }

            if (_outbound.Count >= OutboundQueueCapacity)
            {
                _ = Interlocked.Increment(ref _dropped);
                return;
            }

            _outbound.Enqueue(copy);
        }

        _ = _wake.Set();
    }

    private void Wake()
    {
        _ = _wake.Set();
    }

    private void Run()
    {
        PluginLog.Info("Stack thread started");

        var failures = 0;

        while (!_stopping)
        {
            // Per pass, not around the loop. A throw here used to end the thread, which left the
            // tunnel up and carrying nothing for the rest of the activation - the worst failure this
            // has, because everything above still reports connected. One bad pass is survivable;
            // what is not survivable is losing the thread over it.
            try
            {
                var worked = DrainOutbound();

                // Inbound, timers and anything a channel signalled.
                worked |= _stack.RunOnce();

                // One ring per pass, however many packets it produced.
                _sink.Flush();

                failures = 0;
                ReportIfDue();

                if (!worked)
                {
                    _ = _wake.WaitOne(IdleWait);
                }
            }
            catch (Exception ex)
            {
                failures++;
                PluginLog.Error($"The stack thread failed a pass ({failures} in a row)", ex);

                if (failures >= MaximumConsecutiveFailures)
                {
                    // Bounded: a fault that recurs every pass is a spin, not a hiccup, and burning a
                    // core to log it helps nobody.
                    PluginLog.Error("Giving up on the stack thread; the tunnel will carry nothing");
                    break;
                }

                // Not a hot loop while it recovers.
                _ = _wake.WaitOne(IdleWait);
            }
        }

        PluginLog.Info($"Stack thread stopped — {Summarize()}");
    }

    /// <summary>
    /// Writes the counters if the interval has elapsed.
    /// </summary>
    private void ReportIfDue()
    {
        var now = Environment.TickCount64;

        if (now - _lastReport < (long)ReportInterval.TotalMilliseconds)
        {
            return;
        }

        _lastReport = now;
        PluginLog.Info($"Stack — {Summarize()}");
    }

    /// <summary>
    /// The counters worth judging a run by, in one line.
    /// </summary>
    private string Summarize()
    {
        var dns = _stack.DnsCounters;

        // Rates since the last report, which is what a ceiling shows up in - totals hide it.
        var now = Environment.TickCount64;
        var seconds = Math.Max(1.0, (now - _lastRateAt) / 1000.0);

        var inBytes = _sink.BytesWritten;
        var outBytes = Interlocked.Read(ref Counters.BytesSent);
        var down = (inBytes - _lastIn) * 8.0 / seconds / 1_000_000.0;
        var up = (outBytes - _lastOut) * 8.0 / seconds / 1_000_000.0;

        _lastIn = inBytes;
        _lastOut = outBytes;
        _lastRateAt = now;

        // The transport's own read profile: how many socket reads that traffic cost, how big they
        // were, and how long each one blocked the message listener for.
        var reads = Renci.SshNet.Connection.StreamSocketSshTransport.ReadCount;
        var readBytes = Renci.SshNet.Connection.StreamSocketSshTransport.BytesRead;
        var readTicks = Renci.SshNet.Connection.StreamSocketSshTransport.ReadTicks;

        var deltaReads = reads - _lastReads;
        var averageRead = deltaReads > 0 ? (readBytes - _lastReadBytes) / (double)deltaReads : 0;
        var microsPerRead = deltaReads > 0
            ? (readTicks - _lastReadTicks) * 1_000_000.0 / Stopwatch.Frequency / deltaReads
            : 0;

        _lastReads = reads;
        _lastReadBytes = readBytes;
        _lastReadTicks = readTicks;

        var adjusts = Renci.SshNet.DirectTcpipStream.WindowAdjustsSent;
        var credited = Renci.SshNet.DirectTcpipStream.WindowBytesCredited;
        var deltaAdjusts = adjusts - _lastAdjusts;
        var creditRate = (credited - _lastCredited) * 8.0 / seconds / 1_000_000.0;
        _lastAdjusts = adjusts;
        _lastCredited = credited;

        return $"{_stack.FlowCount} flow(s) open over {_factory.LiveChannels} live channel(s), down {down:F1} Mbit/s, up {up:F1} Mbit/s " +
               $"({_sink.Stalls} platform stall(s), {Interlocked.Read(ref Counters.WindowFull)} window-full); " +
               $"credit {deltaAdjusts / seconds:F1} adjust/s worth {creditRate:F1} Mbit/s; " +
               $"transport {deltaReads / seconds:F0} read/s avg {averageRead:F0} B in {microsPerRead:F0} us; " +
               $"{_stack.Retransmissions} retransmission(s), {_refusals.RefusedFromCache} refused from cache; " +
               $"{Dropped} outbound packet(s) dropped, {_stack.Dropped} uninteresting; " +
               $"DNS {dns.Answered} answered, {dns.Truncated} truncated, {dns.Dropped} dropped " +
               $"over {dns.Channels} channel(s)";
    }

    private bool DrainOutbound()
    {
        var worked = false;

        while (true)
        {
            byte[] packet;

            lock (_gate)
            {
                if (_outbound.Count == 0)
                {
                    return worked;
                }

                packet = _outbound.Dequeue();
            }

            _ = _stack.Offer(packet);
            worked = true;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _stopping = true;
        _ = _wake.Set();

        // Bounded: a stack thread that will not stop must not hold up the teardown the platform is
        // waiting on.
        var stopped = _thread.Join(TimeSpan.FromSeconds(2));

        if (stopped)
        {
            // Only once the thread is gone: the stack is single-threaded by contract, and releasing
            // its channels from under a running loop would break that at the worst moment.
            _stack.Dispose();
        }

        _wake.Dispose();
    }
}
