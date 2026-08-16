using System;
using System.Collections.Generic;
using System.Threading;
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
/// What it carries is raw, owned <c>IVpnPacketBuffer</c> pointers, not projected objects: the
/// projection costs an RCW per acquired buffer, on the packet path, for an object that lives
/// microseconds. Owning raw references makes every disposition explicit — a dequeued pointer is
/// appended and released, a failed one goes back through <see cref="Return"/>, and teardown ends
/// in <see cref="ReleaseAll"/> — because nothing here has a finalizer to catch a mistake.
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
    /// <para>
    /// This is the tunnel's inbound speed limit: throughput cannot exceed the buffers in flight
    /// divided by the doorbell round trip, and at 48 buffers of 1360 bytes over the measured ~55 ms
    /// that is 9.5 Mbit/s - precisely the ceiling every download hit while a bound `ssh -D` on the
    /// same machine, same server and same connected VPN ran at 282. Every layer above was cleared by
    /// measurement first: the SSH window never filled, the transport made no difference, and the
    /// backpressure chain simply propagated this bound up to the server's pacing.
    /// </para>
    /// <para>
    /// Raising it is only safe with the fairness quantum in TcpFlow. The first attempt at 512
    /// predated that quantum, and the stack spent so long filling the sink that the outbound queue
    /// overflowed and dropped 4566 packets - lost acknowledgements kill connections rather than
    /// slowing them. With the quantum bounding inbound work per pass, the outbound queue drains
    /// every pass whatever this is set to.
    /// </para>
    /// <para>
    /// The pool's real size is undocumented, so this may be more than the platform will lend. An
    /// acquisition that fails is counted and refused, which is the same backpressure as a full
    /// queue.
    /// </para>
    /// </remarks>
    public const int Capacity = 512;

    /// <summary>
    /// Keeps the projected channel alive; its object reference is what the raw pointer was taken
    /// from, and other parts of the plug-in still use the projected API on it.
    /// </summary>
    private readonly VpnChannel _channel;

    private readonly Queue<IntPtr> _queue = new(Capacity);
    private readonly object _gate = new();

    /// <summary>Owned <c>IVpnChannel2</c> reference; the receive-buffer acquire goes through it.</summary>
    private IntPtr _channel2;

    private int _outstanding;
    private int _draining;
    private long _lastDrainStarted;

    /// <summary>How many threads are inside the platform's acquire call right now.</summary>
    /// <remarks>
    /// Exists for one race: teardown joins the producer threads with <em>bounded</em> waits and
    /// proceeds regardless, so <see cref="ReleaseAll"/> can run while a straggler is still inside
    /// the call through <see cref="_channel2"/>. Releasing the pointer under that call would be a
    /// use-after-free the old projected path never had — the RCW held its own reference. The last
    /// acquirer to leave performs the deferred release instead.
    /// </remarks>
    private int _acquiring;

    private bool _closed;

    /// <summary>
    /// Terminal: every pointer still held has been released, and every pointer handed in from now
    /// on is released immediately instead of stored — nothing will ever drain this queue again.
    /// </summary>
    private bool _released;

    public InboundPacketQueue(VpnChannel channel)
    {
        ArgumentNullException.ThrowIfNull(channel);

        _channel = channel;

        // Both the acquisition of the pointer every packet will go through, and the connect-time
        // self-check that the IID and the QI machinery are right - failing loudly here beats
        // dereferencing garbage under traffic.
        var hr = VpnChannelAbi.GetChannel2(channel, out _channel2);
        if (hr < 0)
        {
            throw VpnChannelAbi.FailureFor(hr, "The channel does not expose IVpnChannel2; the raw packet path cannot run");
        }
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
    /// <param name="packet">Receives an owned <c>IVpnPacketBuffer</c> pointer.</param>
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
    public bool TryAcquire(out IntPtr packet)
    {
        packet = default;

        lock (_gate)
        {
            if (_closed || _outstanding >= Capacity)
            {
                return false;
            }

            _outstanding++;
            _acquiring++;
        }

        // Outside the gate: this is a cross-process platform call, and holding the lock across it
        // would block the platform thread's dequeue for its duration.
        var hr = VpnChannelAbi.GetReceiveBuffer(_channel2, out packet);

        var releasePacket = false;
        var deferredChannel = default(IntPtr);

        lock (_gate)
        {
            _acquiring--;

            if (hr < 0 || packet == default)
            {
                _outstanding--;
            }
            else if (_released)
            {
                // Torn down while we were inside the call. The pointer is ours and nobody will
                // ever drain it, so it is released rather than borrowed.
                releasePacket = true;
                _outstanding--;
            }

            if (_released && _acquiring == 0 && _channel2 != default)
            {
                deferredChannel = _channel2;
                _channel2 = default;
            }
        }

        if (releasePacket)
        {
            VpnChannelAbi.Release(packet);
            packet = default;
        }

        VpnChannelAbi.Release(deferredChannel);

        if (hr < 0)
        {
            PluginLog.Error($"The platform would not lend a receive buffer (0x{hr:X8})");
        }

        return packet != default;
    }

    /// <summary>
    /// Queues a filled buffer for the platform to collect, taking over its reference.
    /// </summary>
    /// <returns>
    /// <see langword="true"/> if the queue was empty and this made it non-empty — the transition
    /// on which the producer owes a doorbell ring.
    /// </returns>
    /// <remarks>
    /// <para>
    /// A buffer queued after the queue closed is still queued: it has to be given back, and the
    /// final drain is what does that. Only after <see cref="ReleaseAll"/> — when no drain will
    /// ever come — is it released instead.
    /// </para>
    /// <para>
    /// The transition is the ring's whole economy. Every doorbell datagram becomes work the
    /// platform's event prolog must complete before <em>any</em> activation can proceed — dumped
    /// mid-stall, the 90-second-old activation was inside
    /// <c>VpnExeHlpProcessProlog → VpnChannelImpl::CompleteDelivery</c>, fed by per-batch rings at
    /// line rate. Ringing per transition, with the drain's own exit ring covering whatever it
    /// leaves behind, keeps a non-empty queue always owed a visit by induction while sending tens
    /// of datagrams a second instead of hundreds.
    /// </para>
    /// </remarks>
    public bool Enqueue(IntPtr packet)
    {
        var release = false;
        var transition = false;

        lock (_gate)
        {
            if (_released)
            {
                release = true;
                _outstanding--;
            }
            else
            {
                transition = _queue.Count == 0;
                _queue.Enqueue(packet);
            }
        }

        if (release)
        {
            VpnChannelAbi.Release(packet);
        }

        return transition;
    }

    /// <summary>
    /// Gives back a buffer that was acquired but never filled, releasing it and its slot.
    /// </summary>
    /// <remarks>
    /// The failure path's counterpart to <see cref="Enqueue"/>. Without it a producer that
    /// acquired and then failed leaks the reference <em>and</em> permanently charges the failure
    /// against <see cref="Capacity"/> — which is exactly what the old projected path silently did.
    /// </remarks>
    public void Return(IntPtr packet)
    {
        lock (_gate)
        {
            _outstanding--;
        }

        VpnChannelAbi.Release(packet);
    }

    /// <summary>
    /// Takes the next buffer to hand back, if there is one. The caller takes over the reference.
    /// </summary>
    /// <param name="packet">Receives the owned pointer.</param>
    /// <returns>
    /// <see langword="true"/> if a buffer was taken; otherwise, <see langword="false"/>.
    /// </returns>
    public bool TryDequeue(out IntPtr packet)
    {
        lock (_gate)
        {
            if (!_queue.TryDequeue(out var queued))
            {
                packet = default;
                return false;
            }

            _outstanding--;
            packet = queued;
            return true;
        }
    }

    /// <summary>
    /// Gets a value indicating whether anything is queued right now.
    /// </summary>
    public bool HasQueued
    {
        get
        {
            lock (_gate)
            {
                return _queue.Count > 0;
            }
        }
    }

    /// <summary>
    /// Gets a value indicating whether a decapsulate call is draining the queue right now.
    /// </summary>
    /// <remarks>
    /// The producer skips its doorbell ring while this is set: the platform is already here, and
    /// every ring becomes pending work its event pump has to clear before the activation that runs
    /// the pump can complete - which, at line rate, it otherwise never does, and the platform
    /// kills any activation that runs past 90 seconds. The drain's exit ring covers whatever was
    /// queued while it ran, so a skipped ring is deferred, never lost.
    /// </remarks>
    public bool IsDraining => Volatile.Read(ref _draining) != 0;

    /// <summary>Marks the start of a decapsulate drain.</summary>
    public void BeginDrain()
    {
        Volatile.Write(ref _lastDrainStarted, Environment.TickCount64);
        Volatile.Write(ref _draining, 1);
    }

    /// <summary>
    /// Gets how long it has been since the platform last came to drain, for the safety re-ring.
    /// </summary>
    /// <remarks>
    /// Transition rings plus exit rings cover every ordinary path; what they cannot survive is an
    /// actual lost datagram. A queue that stays non-empty with no drain for longer than this
    /// suggests the ring went missing, and the producer sends another.
    /// </remarks>
    public long MillisecondsSinceLastDrain => Environment.TickCount64 - Volatile.Read(ref _lastDrainStarted);

    /// <summary>Marks the end of a decapsulate drain.</summary>
    public void EndDrain()
    {
        Volatile.Write(ref _draining, 0);
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

    /// <summary>
    /// Releases every reference this queue still holds. Terminal.
    /// </summary>
    /// <remarks>
    /// For teardown, after the final drain has had its chance. A released buffer is not
    /// <em>returned</em> — the platform never gets it back through Decapsulate — but that is no
    /// worse than the old path, where the same buffers waited for the GC finalizer; with raw
    /// pointers the release must be explicit or it never happens. The channel pointer's release is
    /// deferred to the last in-flight acquirer when one is still inside the platform call, because
    /// teardown's thread joins are bounded and proceed regardless.
    /// </remarks>
    public void ReleaseAll()
    {
        List<IntPtr>? drained = null;
        var channel2 = default(IntPtr);

        lock (_gate)
        {
            _closed = true;
            _released = true;

            if (_queue.Count > 0)
            {
                drained = new List<IntPtr>(_queue.Count);

                while (_queue.TryDequeue(out var packet))
                {
                    drained.Add(packet);
                    _outstanding--;
                }
            }

            if (_acquiring == 0)
            {
                channel2 = _channel2;
                _channel2 = default;
            }
        }

        if (drained is not null)
        {
            foreach (var packet in drained)
            {
                VpnChannelAbi.Release(packet);
            }
        }

        VpnChannelAbi.Release(channel2);
    }
}
