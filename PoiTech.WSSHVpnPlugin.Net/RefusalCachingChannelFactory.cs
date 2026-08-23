using System;
using System.Collections.Generic;
using System.Threading;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// Remembers destinations the server just refused, and refuses them again locally for a while.
/// </summary>
/// <remarks>
/// <para>
/// A machine that keeps a connection alive to something the tunnel cannot serve retries it
/// steadily, and every retry costs a channel open: a round trip to the SSH server, a slot under
/// the live-channel cap, and — for an unreachable destination — the server's own connect timeout.
/// Measured on an idle machine before the exclusion routes existed, connections to the local
/// subnet alone produced a steady stream of doomed opens. The verdict was already known each time;
/// this remembers it.
/// </para>
/// <para>
/// Only <see cref="ByteChannelOpenFailure.Refused"/> is cached — the server's own statement about
/// the destination. Local failures say nothing about the address: a single rekey pause can time
/// out every open in flight at once, and caching those would blackhole destinations that were
/// fine, the configured DNS servers first among them.
/// </para>
/// <para>
/// The dictionary is locked because the inner factory answers on its own threads, while new opens
/// arrive on the stack's. The cache may be dropped at any moment without harm — it can only save
/// round trips, never change an answer — which is what licenses the crude full clear when it
/// fills.
/// </para>
/// </remarks>
internal sealed class RefusalCachingChannelFactory : IByteChannelFactory
{
    /// <summary>
    /// How long a refusal is held against the destination.
    /// </summary>
    /// <remarks>
    /// Long enough to absorb a retry burst — browsers retry a refused connection within
    /// milliseconds, and keep-alive probes within seconds — and short enough that a service
    /// coming up behind the server is reachable again on a human timescale.
    /// </remarks>
    private static readonly TimeSpan TimeToLive = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The most destinations remembered at once, so a scan of thousands of refused addresses
    /// cannot turn the cache into a leak.
    /// </summary>
    private const int MaximumEntries = 256;

    private readonly IByteChannelFactory _inner;
    private readonly IStackClock _clock;
    private readonly Lock _gate = new();
    private readonly Dictionary<(IpAddr Address, ushort Port), TimeSpan> _refused = new();

    private long _refusedFromCache;

    public RefusalCachingChannelFactory(IByteChannelFactory inner, IStackClock clock)
    {
        _inner = inner;
        _clock = clock;
    }

    /// <summary>Gets how many opens were refused from the cache, without a round trip.</summary>
    public long RefusedFromCache => Interlocked.Read(ref _refusedFromCache);

    /// <inheritdoc/>
    public void BeginOpen(IpAddr address, ushort port, Action<IByteChannel> onOpened, Action<ByteChannelOpenFailure> onFailed)
    {
        var key = (address, port);

        lock (_gate)
        {
            if (_refused.TryGetValue(key, out var expires))
            {
                if (_clock.Now < expires)
                {
                    _refusedFromCache++;
                    onFailed(ByteChannelOpenFailure.Refused);
                    return;
                }

                _ = _refused.Remove(key);
            }
        }

        _inner.BeginOpen(
            address,
            port,
            onOpened,
            reason =>
            {
                if (reason == ByteChannelOpenFailure.Refused)
                {
                    Remember(key);
                }

                onFailed(reason);
            });
    }

    private void Remember((IpAddr Address, ushort Port) key)
    {
        lock (_gate)
        {
            if (_refused.Count >= MaximumEntries && !_refused.ContainsKey(key))
            {
                Purge();
            }

            _refused[key] = _clock.Now + TimeToLive;
        }
    }

    /// <summary>
    /// Drops the expired entries, or everything when nothing has expired: forgetting a refusal
    /// costs one round trip to relearn it, keeping too many costs memory forever.
    /// </summary>
    private void Purge()
    {
        var now = _clock.Now;
        List<(IpAddr, ushort)>? expired = null;

        foreach (var pair in _refused)
        {
            if (now >= pair.Value)
            {
                (expired ??= new List<(IpAddr, ushort)>()).Add(pair.Key);
            }
        }

        if (expired is null)
        {
            _refused.Clear();
            return;
        }

        foreach (var key in expired)
        {
            _ = _refused.Remove(key);
        }
    }
}
