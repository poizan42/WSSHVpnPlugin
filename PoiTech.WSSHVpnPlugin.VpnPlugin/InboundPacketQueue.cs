using System;
using System.Collections.Generic;
using Windows.Networking.Vpn;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Carries inbound packets from the threads that build them to the platform thread that hands them
/// back.
/// </summary>
/// <remarks>
/// <para>
/// The platform offers no way to inject a packet from an arbitrary thread: a buffer it lends us has
/// to be returned through <see cref="SSHVpnPlugin.Encapsulate"/> or
/// <see cref="SSHVpnPlugin.Decapsulate"/>, and only the latter is an inbound path. So the producer
/// acquires the platform's own buffer, writes the packet <em>directly into it</em>, and queues the
/// buffer; the decapsulate handler does nothing but append what it finds. The queue therefore
/// carries platform buffers, not copies — the packet is written once, and appending it is what
/// returns it.
/// </para>
/// <para>
/// Acquiring is bounded because the platform's buffer pool is not documented to be large, and a
/// plug-in that exhausts it stops being able to request buffers at all. A refused acquisition is
/// not an error: it is the signal to stop producing, which for TCP means advertising a smaller
/// window rather than dropping what has already been accepted.
/// </para>
/// </remarks>
internal sealed class InboundPacketQueue
{
    /// <summary>
    /// The most buffers that may be borrowed from the platform at once.
    /// </summary>
    /// <remarks>
    /// Deliberately modest. The pool's real size is undocumented, and holding more of it than we
    /// need buys nothing: the queue exists to smooth a batch, not to store a backlog.
    /// </remarks>
    public const int Capacity = 48;

    private readonly VpnChannel _channel;
    private readonly Queue<VpnPacketBuffer> _queue = new(Capacity);
    private readonly object _gate = new();

    private int _outstanding;
    private bool _closed;

    public InboundPacketQueue(VpnChannel channel)
    {
        ArgumentNullException.ThrowIfNull(channel);

        _channel = channel;
    }

    /// <summary>
    /// Gets a value indicating whether a buffer could be borrowed right now.
    /// </summary>
    /// <value>
    /// <see langword="true"/> if there is room; otherwise, <see langword="false"/>.
    /// </value>
    /// <remarks>
    /// Free of side effects, so the stack can ask before doing work it would have to throw away.
    /// It reserves nothing, so a caller that asks and then does not take is not charged for it.
    /// </remarks>
    public bool HasCapacity
    {
        get
        {
            lock (_gate)
            {
                return !_closed && _outstanding < Capacity;
            }
        }
    }

    /// <summary>
    /// Gets a value indicating whether the queue has been closed and drained, so that the channel
    /// can be stopped.
    /// </summary>
    public bool IsFinished
    {
        get
        {
            lock (_gate)
            {
                return _closed && _queue.Count == 0;
            }
        }
    }

    /// <summary>
    /// Borrows a receive buffer from the platform to write a packet into.
    /// </summary>
    /// <param name="buffer">Receives the borrowed buffer.</param>
    /// <returns>
    /// <see langword="true"/> if a buffer was borrowed; <see langword="false"/> if the queue is
    /// closed or already holds as many as it may.
    /// </returns>
    /// <remarks>
    /// Called from the producer's thread, not the platform's. That is undocumented but is what the
    /// reference implementation does in production; if it turns out not to hold, the fallback is to
    /// queue plain arrays and copy them into platform buffers inside the decapsulate handler, at the
    /// cost of a second copy per packet.
    /// </remarks>
    public bool TryAcquire(out VpnPacketBuffer buffer)
    {
        lock (_gate)
        {
            if (_closed || _outstanding >= Capacity)
            {
                buffer = null!;
                return false;
            }

            _outstanding++;
        }

        try
        {
            buffer = _channel.GetVpnReceivePacketBuffer();
        }
        catch (Exception ex)
        {
            lock (_gate)
            {
                _outstanding--;
            }

            PluginLog.Error("The platform would not lend a receive buffer", ex);
            buffer = null!;
            return false;
        }

        return true;
    }

    /// <summary>
    /// Queues a filled buffer for the platform to collect.
    /// </summary>
    /// <remarks>
    /// A buffer queued after the queue closed is still queued: it has to be given back, and the
    /// final drain is what does that.
    /// </remarks>
    public void Enqueue(VpnPacketBuffer buffer)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        lock (_gate)
        {
            _queue.Enqueue(buffer);
        }
    }

    /// <summary>
    /// Takes the next buffer to hand back, if there is one.
    /// </summary>
    /// <param name="buffer">Receives the buffer.</param>
    /// <returns>
    /// <see langword="true"/> if a buffer was taken; otherwise, <see langword="false"/>.
    /// </returns>
    public bool TryDequeue(out VpnPacketBuffer buffer)
    {
        lock (_gate)
        {
            if (!_queue.TryDequeue(out var queued))
            {
                buffer = null!;
                return false;
            }

            _outstanding--;
            buffer = queued;
            return true;
        }
    }

    /// <summary>
    /// Stops further production, leaving whatever is queued to be drained.
    /// </summary>
    public void Close()
    {
        lock (_gate)
        {
            _closed = true;
        }
    }
}
