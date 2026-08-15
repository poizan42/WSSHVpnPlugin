using System;
using System.Collections.Generic;
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

    private readonly StackLoop _stack;
    private readonly InboundPacketSink _sink;
    private readonly Queue<byte[]> _outbound = new();
    private readonly object _gate = new();
    private readonly AutoResetEvent _wake = new(initialState: false);
    private readonly Thread _thread;

    private volatile bool _stopping;
    private int _disposed;
    private long _dropped;

    public PacketPath(SshClient client, InboundPacketQueue queue, IOuterTransport transport)
    {
        _sink = new InboundPacketSink(queue, transport);
        _stack = new StackLoop(new SshByteChannelFactory(client, Wake), _sink, new MonotonicClock());

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

        try
        {
            while (!_stopping)
            {
                var worked = DrainOutbound();

                // Inbound, timers and anything a channel signalled.
                worked |= _stack.RunOnce();

                // One ring per pass, however many packets it produced.
                _sink.Flush();

                if (!worked)
                {
                    _ = _wake.WaitOne(IdleWait);
                }
            }
        }
        catch (Exception ex)
        {
            PluginLog.Error("The stack thread failed; the tunnel will carry nothing", ex);
        }

        PluginLog.Info($"Stack thread stopped (dropped {Dropped} outbound packet(s), {_stack.Dropped} uninteresting)");
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
        _ = _thread.Join(TimeSpan.FromSeconds(2));
        _wake.Dispose();
    }
}
