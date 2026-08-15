using System;
using System.Threading;
using System.Threading.Tasks;
using PoiTech.WSSHVpnPlugin.Net;
using Renci.SshNet;
using Renci.SshNet.Channels;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Presents an SSH <c>direct-tcpip</c> channel as the stack's byte channel.
/// </summary>
/// <remarks>
/// <para>
/// Thin by design: the stack was written against a seam precisely so that everything SSH-shaped
/// stops here and the stack itself can be tested with no session at all.
/// </para>
/// <para>
/// Thin, but not transparent - nothing here may throw. Every one of these members is called from the
/// stack's own thread, whose loop is wrapped in a single <c>try</c>: an exception does not fail the
/// flow, it <em>exits the loop</em>, and the tunnel then carries nothing for the rest of the
/// activation while still looking connected. The SSH calls underneath throw readily - a session that
/// drops, or a channel the far end closed between the check and the call - so each one is caught here
/// and turned into a channel that reports itself closed, which the stack already knows how to unwind.
/// </para>
/// </remarks>
internal sealed class DirectTcpipByteChannel : IByteChannel
{
    private readonly DirectTcpipStream _stream;
    private bool _faulted;

    public DirectTcpipByteChannel(DirectTcpipStream stream)
    {
        _stream = stream;
    }

    /// <inheritdoc/>
    public bool IsOpen
    {
        get
        {
            if (_faulted)
            {
                return false;
            }

            try
            {
                return _stream.IsOpen;
            }
            catch (Exception ex)
            {
                Fault(ex);
                return false;
            }
        }
    }

    /// <inheritdoc/>
    public bool IsPeerEof
    {
        get
        {
            try
            {
                return !_faulted && _stream.IsPeerEof;
            }
            catch (Exception ex)
            {
                Fault(ex);
                return false;
            }
        }
    }

    /// <summary>
    /// Raised when the channel has data or has changed state, so the stack can be woken.
    /// </summary>
    public event EventHandler<EventArgs>? Signalled;

    /// <summary>
    /// Subscribes to the stream's notifications. Separate from the constructor so the caller can
    /// attach its wake-up before anything can arrive.
    /// </summary>
    public void Start()
    {
        _stream.DataAvailable += OnSignalled;
        _stream.PeerEof += OnSignalled;
        _stream.PeerClosed += OnSignalled;
        _stream.WindowAvailable += OnSignalled;
    }

    /// <inheritdoc/>
    public bool TryRead(out ArraySegment<byte> data)
    {
        if (_faulted)
        {
            data = default;
            return false;
        }

        try
        {
            return _stream.TryRead(out data);
        }
        catch (Exception ex)
        {
            Fault(ex);
            data = default;
            return false;
        }
    }

    /// <inheritdoc/>
    public bool Advance(int count)
    {
        if (_faulted)
        {
            return false;
        }

        try
        {
            return _stream.Advance(count);
        }
        catch (Exception ex)
        {
            Fault(ex);
            return false;
        }
    }

    /// <inheritdoc/>
    public void FlushWindowCredit()
    {
        if (_faulted)
        {
            return;
        }

        try
        {
            _stream.FlushWindowCredit();
        }
        catch (Exception ex)
        {
            Fault(ex);
        }
    }

    /// <inheritdoc/>
    public ByteChannelSendResult TrySend(byte[] data, int offset, int count, out int written)
    {
        written = 0;

        if (_faulted)
        {
            return ByteChannelSendResult.Closed;
        }

        try
        {
            return _stream.TrySend(data, offset, count, out written) switch
            {
                ChannelSendResult.Written => ByteChannelSendResult.Written,
                ChannelSendResult.WindowFull => ByteChannelSendResult.Full,
                _ => ByteChannelSendResult.Closed,
            };
        }
        catch (Exception ex)
        {
            Fault(ex);
            written = 0;
            return ByteChannelSendResult.Closed;
        }
    }

    /// <inheritdoc/>
    public void SendEof()
    {
        if (_faulted)
        {
            return;
        }

        try
        {
            _stream.SendEof();
        }
        catch (Exception ex)
        {
            Fault(ex);
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        try
        {
            _stream.DataAvailable -= OnSignalled;
            _stream.PeerEof -= OnSignalled;
            _stream.PeerClosed -= OnSignalled;
            _stream.WindowAvailable -= OnSignalled;
            _stream.Dispose();
        }
        catch (Exception ex)
        {
            // Disposal failing is not actionable, but letting it escape ends the stack thread.
            Fault(ex);
        }
    }

    /// <summary>
    /// Records that the channel is unusable, once.
    /// </summary>
    /// <remarks>
    /// Reported once per channel rather than per call: a dead session fails every flow at line rate,
    /// and logging each one would bury the first failure - the only one that says what happened.
    /// </remarks>
    private void Fault(Exception ex)
    {
        if (_faulted)
        {
            return;
        }

        _faulted = true;
        PluginLog.Error("A channel failed and will be treated as closed", ex);
    }

    private void OnSignalled(object? sender, EventArgs e)
    {
        Signalled?.Invoke(this, EventArgs.Empty);
    }
}

/// <summary>
/// Opens <c>direct-tcpip</c> channels for the stack.
/// </summary>
internal sealed class SshByteChannelFactory : IByteChannelFactory
{
    /// <summary>
    /// How many opens may be in flight at once.
    /// </summary>
    /// <remarks>
    /// An open blocks its thread until the server answers, and a destination the server cannot reach
    /// blocks it for the full SSH timeout. A Windows machine offers a steady supply of those — every
    /// connection to a host on the local network arrives here and cannot be served — so without a
    /// bound they accumulate on the thread pool and starve the opens that would have succeeded.
    /// </remarks>
    private const int MaximumConcurrentOpens = 8;

    private readonly SshClient _client;
    private readonly Action _wake;
    private readonly SemaphoreSlim _openSlots = new(MaximumConcurrentOpens, MaximumConcurrentOpens);

    public SshByteChannelFactory(SshClient client, Action wake)
    {
        _client = client;
        _wake = wake;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Opening is a round trip, so it happens on a worker: the stack's own thread must never block,
    /// and a channel open would hold it for the length of a network exchange.
    /// </remarks>
    public void BeginOpen(uint address, ushort port, Action<IByteChannel> onOpened, Action onFailed)
    {
        var host = Ipv4Format(address);

        if (!_openSlots.Wait(0))
        {
            // Refused rather than queued. The peer is told at once and can retry, which is far
            // better than holding its SYN while a queue of doomed opens drains.
            PluginLog.Error($"Refusing a channel to {host}:{port}: {MaximumConcurrentOpens} opens already in flight");
            onFailed();
            _wake();
            return;
        }

        _ = Task.Run(() =>
        {
            try
            {
                var stream = _client.CreateDirectTcpipStream(host, port);
                var channel = new DirectTcpipByteChannel(stream);
                channel.Signalled += (_, _) => _wake();
                channel.Start();

                onOpened(channel);
            }
            catch (Exception ex)
            {
                PluginLog.Error($"Could not open a channel to {host}:{port}: {ex.Message}");
                onFailed();
            }
            finally
            {
                _ = _openSlots.Release();

                // Either way the stack has work to do: answer the handshake, or refuse it.
                _wake();
            }
        });
    }

    private static string Ipv4Format(uint address)
    {
        Span<byte> bytes = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes, address);
        return new System.Net.IPAddress(bytes).ToString();
    }
}

/// <summary>
/// Hands the stack's packets to the platform.
/// </summary>
/// <remarks>
/// The doorbell is rung once per batch by <see cref="Flush"/> rather than per packet. Ringing per
/// packet would be a loopback datagram for each one; ringing only on a transition stalls forever if
/// a single ring is ever lost.
/// </remarks>
internal sealed class InboundPacketSink : IPacketSink
{
    private readonly InboundPacketQueue _queue;
    private readonly IOuterTransport _transport;
    private bool _pending;

    public InboundPacketSink(InboundPacketQueue queue, IOuterTransport transport)
    {
        _queue = queue;
        _transport = transport;
    }

    /// <inheritdoc/>
    public bool CanAccept => _queue.HasCapacity;

    /// <inheritdoc/>
    public bool TryWrite(ReadOnlySpan<byte> packet)
    {
        if (!_queue.TryAcquire(out var buffer))
        {
            return false;
        }

        try
        {
            packet.CopyTo(VpnPacketBufferAccess.GetSpan(buffer));
            buffer.Buffer.Length = (uint)packet.Length;
            _queue.Enqueue(buffer);
            _pending = true;
            return true;
        }
        catch (Exception ex)
        {
            PluginLog.Error("Failed to hand a packet to the platform", ex);
            return false;
        }
    }

    /// <summary>Rings the doorbell if anything was written since the last call.</summary>
    public void Flush()
    {
        if (!_pending)
        {
            return;
        }

        _pending = false;
        _transport.RingDoorbell();
    }
}

/// <summary>
/// The stack's clock, monotonic and cheap.
/// </summary>
internal sealed class MonotonicClock : IStackClock
{
    /// <inheritdoc/>
    public TimeSpan Now => TimeSpan.FromMilliseconds(Environment.TickCount64);
}
