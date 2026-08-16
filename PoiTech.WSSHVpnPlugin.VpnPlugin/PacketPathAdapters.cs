using System;
using System.Threading;
using System.Threading.Tasks;
using PoiTech.WSSHVpnPlugin.Net;
using Renci.SshNet;
using Renci.SshNet.Channels;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Throughput counters, shared across every channel.
/// </summary>
/// <remarks>
/// Deliberately crude and process-wide. Throughput has so far been inferred from a browser speed
/// test, which measures the whole path and cannot say which end of it is the limit - raising the
/// channel window sixteenfold changed nothing, and without numbers from inside the stack there was
/// no way to tell whether the bytes were not arriving or not being delivered.
/// </remarks>
internal static class Counters
{
    /// <summary>Bytes written to SSH channels: what the client is uploading.</summary>
    public static long BytesSent;

    /// <summary>How often a channel's remote window had no room.</summary>
    public static long WindowFull;
}

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
    private readonly Action? _released;
    private bool _faulted;
    private bool _disposed;

    public DirectTcpipByteChannel(DirectTcpipStream stream, Action? released = null)
    {
        _stream = stream;
        _released = released;
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
            var result = _stream.TrySend(data, offset, count, out written);

            if (written > 0)
            {
                _ = Interlocked.Add(ref Counters.BytesSent, written);
            }

            if (result == ChannelSendResult.WindowFull)
            {
                _ = Interlocked.Increment(ref Counters.WindowFull);
            }

            return result switch
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
    /// <remarks>
    /// The unsubscription is synchronous, so a dead stream cannot keep raising
    /// <see cref="Signalled"/> into a flow that no longer exists. Only the stream's own disposal is
    /// deferred: it sends the close sequence and used to wait a round trip for the server's answer,
    /// and this runs on the stack's thread, which must never wait on the network.
    /// </remarks>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        try
        {
            _stream.DataAvailable -= OnSignalled;
            _stream.PeerEof -= OnSignalled;
            _stream.PeerClosed -= OnSignalled;
            _stream.WindowAvailable -= OnSignalled;
        }
        catch (Exception ex)
        {
            // Disposal failing is not actionable, but letting it escape ends the stack thread.
            Fault(ex);
        }

        _ = DisposeStreamAsync();
    }

    /// <summary>
    /// Disposes the stream without holding the calling thread, and releases the factory's
    /// live-channel slot once it is done.
    /// </summary>
    /// <remarks>
    /// Fire-and-forget, but the exceptions are observed: an unobserved faulted task is a crash
    /// vector in a background-task host.
    /// </remarks>
    private async Task DisposeStreamAsync()
    {
        try
        {
            await _stream.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Fault(ex);
        }
        finally
        {
            _released?.Invoke();
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
    /// How many channels may be alive at once: opens in flight, open channels, and abandoned opens
    /// still awaiting the server's answer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This replaced a pool of 8 blocking opens, and the difference in kind matters more than the
    /// number. An open used to park a thread until the server answered — a destination the server
    /// cannot reach parked it for the full 30-second SSH timeout, and a Windows machine offers a
    /// steady supply of those. Under a sustained download the refusals cascaded into a browser retry
    /// storm that killed the transfer; measured on an idle machine, 4.2 opens/s arrived against
    /// those 8 slots. Now an open in flight is a <c>TaskCompletionSource</c> and a timed-out one is
    /// an object waiting for the server's answer, so the bound is on memory and server-side channel
    /// state, not on threads.
    /// </para>
    /// <para>
    /// The count deliberately includes the abandoned-awaiting-answer opens: each one is a channel
    /// the server may still be holding, so they are exactly what a cap on server-side state has to
    /// cover.
    /// </para>
    /// </remarks>
    private const int MaximumLiveChannels = 128;

    /// <summary>
    /// How much the far end may send us before it has to wait for a window adjustment.
    /// </summary>
    /// <remarks>
    /// This is the inbound speed limit, and the fork's 8 KiB default made it a severe one: a window
    /// adjustment costs a round trip to the SSH server, so throughput is bounded by window over
    /// round-trip time however fast the link is. Measured through the tunnel at 48 ms: 8 KiB gave
    /// 633 kbit/s, 128 KiB gave 7.89 Mbit/s, and `ssh -D` to the same server over the same link gave
    /// 278 Mbit/s. The difference was never SSH - OpenSSH advertises 2 MiB
    /// (CHAN_TCP_WINDOW_DEFAULT, 64 x 32 KiB), and 2 MiB over 48 ms is about 340 Mbit/s, which is
    /// the bracket its measurement falls in.
    ///
    /// So this matches OpenSSH. What made that affordable is that DirectTcpipStream now grows its
    /// receive buffer on demand rather than allocating the window up front: a channel per TCP flow
    /// means the window would otherwise be paid for on every idle connection.
    /// </remarks>
    private const uint ChannelWindowSize = 2 * 1024 * 1024;

    /// <summary>
    /// The per-channel receive buffer, which must not be smaller than the window we advertise.
    /// </summary>
    /// <remarks>
    /// Sized to the window exactly: the far end is entitled to fill the window, and
    /// <c>DirectTcpipStream</c> treats a buffer smaller than that as a configuration error rather
    /// than something to handle at runtime. The cost is per live channel, so it is bounded by
    /// whatever limits those.
    /// </remarks>
    private const int ChannelBufferSize = (int)ChannelWindowSize;

    private readonly SshClient _client;
    private readonly Action _wake;
    private readonly TimeSpan _openTimeout;
    private int _live;
    private int _reportedWindows;

    public SshByteChannelFactory(SshClient client, Action wake, TimeSpan openTimeout)
    {
        _client = client;
        _wake = wake;
        _openTimeout = openTimeout;
    }

    /// <summary>Gets how many channels are alive right now, for the periodic report.</summary>
    public int LiveChannels => Volatile.Read(ref _live);

    /// <inheritdoc/>
    /// <remarks>
    /// The open starts on a worker because sending the request can block — on the socket lock, or
    /// for the length of a rekey — and the stack's own thread must never wait on either. The worker
    /// is released at the first await rather than held for the server's answer.
    /// </remarks>
    public void BeginOpen(uint address, ushort port, Action<IByteChannel> onOpened, Action<ByteChannelOpenFailure> onFailed)
    {
        var host = Ipv4Format(address);

        if (Interlocked.Increment(ref _live) > MaximumLiveChannels)
        {
            _ = Interlocked.Decrement(ref _live);

            // Refused rather than queued. The peer is told at once and can retry, which is far
            // better than holding its SYN while a queue of doomed opens drains. Local, not
            // Refused: the cap says nothing about the destination.
            PluginLog.Error($"Refusing a channel to {host}:{port}: {MaximumLiveChannels} channels already live");
            onFailed(ByteChannelOpenFailure.Local);
            _wake();
            return;
        }

        _ = Task.Run(() => OpenAsync(host, port, onOpened, onFailed));
    }

    /// <summary>
    /// Opens one channel, bounded by the open timeout rather than by SSH's 30-second one.
    /// </summary>
    /// <remarks>
    /// A timed-out open is abandoned, never disposed: the server owes an answer, and the channel
    /// stays subscribed until it arrives, then closes anything that was granted. The live-channel
    /// slot is held for that whole time, because until the answer comes the server may be holding
    /// the channel too.
    /// </remarks>
    private async Task OpenAsync(string host, ushort port, Action<IByteChannel> onOpened, Action<ByteChannelOpenFailure> onFailed)
    {
        DirectTcpipStream? stream = null;

        try
        {
            stream = _client.CreateUnopenedDirectTcpipStream(ChannelBufferSize, ChannelWindowSize);

            using (var timeout = new CancellationTokenSource(_openTimeout))
            {
                await stream.OpenAsync(host, port, timeout.Token).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            var reason = ex is OperationCanceledException
                ? $"no answer within {_openTimeout.TotalSeconds:0.#} s"
                : ex.Message;
            PluginLog.Error($"Could not open a channel to {host}:{port}: {reason}");

            // Only the server's own verdict about the destination is reported as a refusal - it is
            // what the negative cache may remember. A timeout, a dead session, or a server that is
            // merely out of resources says nothing about the address.
            var failure = ex is Renci.SshNet.Common.SshChannelOpenException { IsAboutTheDestination: true }
                ? ByteChannelOpenFailure.Refused
                : ByteChannelOpenFailure.Local;

            // The peer is refused before the reap, not after: the reap can take as long as the
            // server needs to answer, and the flow should not wait on it.
            onFailed(failure);
            _wake();

            if (stream is not null)
            {
                try
                {
                    await stream.AbandonAsync().ConfigureAwait(false);
                }
                catch (Exception reapEx)
                {
                    PluginLog.Error($"Abandoning the open to {host}:{port} failed", reapEx);
                }
            }

            _ = Interlocked.Decrement(ref _live);
            return;
        }

        DirectTcpipByteChannel? channel = null;

        try
        {
            if (Interlocked.Exchange(ref _reportedWindows, 1) == 0)
            {
                // Once per session. What the server grants is the outbound limit, the mirror of
                // the window we advertise for inbound, and it is worth knowing rather than
                // assuming: OpenSSH's compile-time default is far larger than the fork's.
                PluginLog.Info(
                    $"Channel windows: we advertise {ChannelWindowSize} bytes, " +
                    $"the server granted {stream.RemoteWindowSize} with a {stream.RemotePacketSize}-byte packet limit");
            }

            // The channel owns the live slot from here: its disposal releases it.
            channel = new DirectTcpipByteChannel(stream, () => Interlocked.Decrement(ref _live));
            channel.Signalled += (_, _) => _wake();
            channel.Start();

            onOpened(channel);
            _wake();
        }
        catch (Exception ex)
        {
            PluginLog.Error($"Could not hand the stack its channel to {host}:{port}", ex);
            onFailed(ByteChannelOpenFailure.Local);
            _wake();

            if (channel is not null)
            {
                // Disposing the channel releases the live slot through its callback.
                channel.Dispose();
            }
            else
            {
                await stream.DisposeAsync().ConfigureAwait(false);
                _ = Interlocked.Decrement(ref _live);
            }
        }
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
    private long _bytesWritten;
    private long _stalls;
    private bool _pending;

    /// <summary>0 until the first packet, 1 once the ABI shape check passed, -1 if it failed.</summary>
    private int _verified;

    public InboundPacketSink(InboundPacketQueue queue, IOuterTransport transport)
    {
        _queue = queue;
        _transport = transport;
    }

    /// <inheritdoc/>
    public bool CanAccept => _queue.HasCapacity;

    /// <summary>Gets how many bytes have been handed to the platform.</summary>
    public long BytesWritten => Interlocked.Read(ref _bytesWritten);

    /// <summary>Gets how often the platform's buffer pool had no room.</summary>
    public long Stalls => Interlocked.Read(ref _stalls);

    /// <inheritdoc/>
    /// <remarks>
    /// Raw vtable calls throughout — this runs per packet, and the projected API costs an RCW per
    /// buffer and another per <c>.Buffer</c> get. On any failure the buffer goes back through
    /// <see cref="InboundPacketQueue.Return"/>: dropping it would lose the platform's buffer
    /// <em>and</em> permanently charge it against the queue's budget.
    /// </remarks>
    public unsafe bool TryWrite(ReadOnlySpan<byte> packet)
    {
        if (!_queue.TryAcquire(out var buffer))
        {
            // Worth counting rather than just refusing: if the inbound path is capped by the
            // platform draining buffers rather than by anything upstream, this is where it shows.
            _ = Interlocked.Increment(ref _stalls);
            return false;
        }

        var inner = default(IntPtr);
        var byteAccess = default(IntPtr);

        try
        {
            var hr = VpnChannelAbi.AcquireSpan(buffer, out inner, out byteAccess, out var data, out var capacity);

            if (hr >= 0 && Volatile.Read(ref _verified) == 0)
            {
                if (!VpnChannelAbi.VerifyPacketShape(buffer, inner, capacity, out var why))
                {
                    // A failed shape check means the slot table is wrong for this machine; every
                    // dereference after this point would be garbage. Refuse the path loudly and
                    // permanently rather than corrupt.
                    Volatile.Write(ref _verified, -1);
                    PluginLog.Error($"ABI self-check failed on the first inbound packet: {why}; the inbound path is disabled");
                }
                else
                {
                    Volatile.Write(ref _verified, 1);
                }
            }

            if (Volatile.Read(ref _verified) < 0)
            {
                _queue.Return(buffer);
                return false;
            }

            if (hr >= 0 && packet.Length <= (int)capacity)
            {
                packet.CopyTo(new Span<byte>(data, (int)capacity));
                hr = VpnChannelAbi.SetLength(inner, (uint)packet.Length);
            }
            else if (hr >= 0)
            {
                // ERROR_INSUFFICIENT_BUFFER as an HRESULT: the packet cannot fit the platform's
                // buffer, which is a frame-size configuration problem, not a transient.
                hr = unchecked((int)0x8007007A);
            }

            if (hr < 0)
            {
                _queue.Return(buffer);
                PluginLog.Error($"Failed to hand a packet to the platform (0x{hr:X8})");
                return false;
            }

            _queue.Enqueue(buffer);
            _pending = true;
            _ = Interlocked.Add(ref _bytesWritten, packet.Length);
            return true;
        }
        catch (Exception ex)
        {
            _queue.Return(buffer);
            PluginLog.Error("Failed to hand a packet to the platform", ex);
            return false;
        }
        finally
        {
            VpnChannelAbi.ReleaseSpan(inner, byteAccess);
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
    /// <remarks>
    /// Built from ticks, not <see cref="TimeSpan.FromMilliseconds(double)"/>: that overload rounds
    /// through a double with range checks, and this property is read several times per flow per
    /// stack pass — it showed up by name in a live CPU sample of the stack thread.
    /// </remarks>
    public TimeSpan Now => new(Environment.TickCount64 * TimeSpan.TicksPerMillisecond);
}
