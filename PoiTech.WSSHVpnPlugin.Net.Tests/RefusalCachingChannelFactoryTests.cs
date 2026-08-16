using System;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.Net.Tests;

/// <summary>
/// The negative cache: refusals are remembered against the destination, everything else is not.
/// </summary>
[TestClass]
public class RefusalCachingChannelFactoryTests
{
    private const uint Address = 0x01020304;
    private const ushort Port = 443;

    private FakeChannelFactory _inner = null!;
    private FakeClock _clock = null!;
    private RefusalCachingChannelFactory _cache = null!;

    private int _opened;
    private int _failed;
    private ByteChannelOpenFailure? _lastFailure;

    [TestInitialize]
    public void Initialize()
    {
        _inner = new FakeChannelFactory();
        _clock = new FakeClock();
        _cache = new RefusalCachingChannelFactory(_inner, _clock);
        _opened = 0;
        _failed = 0;
        _lastFailure = null;
    }

    private void Open(uint address = Address, ushort port = Port)
    {
        _cache.BeginOpen(address, port, _ => _opened++, reason =>
        {
            _failed++;
            _lastFailure = reason;
        });
    }

    [TestMethod]
    public void ARefusal_IsAnsweredFromMemoryWhileItHolds()
    {
        _inner.FailOpens = true;
        _inner.FailureReason = ByteChannelOpenFailure.Refused;

        Open();
        Assert.AreEqual(1, _inner.OpenRequests);

        _clock.Advance(TimeSpan.FromSeconds(5));
        Open();

        Assert.AreEqual(1, _inner.OpenRequests, "the verdict was already known; asking again costs a round trip");
        Assert.AreEqual(2, _failed);
        Assert.AreEqual(ByteChannelOpenFailure.Refused, _lastFailure);
        Assert.AreEqual(1, _cache.RefusedFromCache);
    }

    /// <summary>
    /// A local failure says nothing about the destination. A single rekey pause times out every
    /// open in flight at once, and caching those would blackhole destinations that were fine.
    /// </summary>
    [TestMethod]
    public void ALocalFailure_IsNeverRemembered()
    {
        _inner.FailOpens = true;
        _inner.FailureReason = ByteChannelOpenFailure.Local;

        Open();
        Open();

        Assert.AreEqual(2, _inner.OpenRequests, "every open must reach the server again");
        Assert.AreEqual(ByteChannelOpenFailure.Local, _lastFailure);
        Assert.AreEqual(0, _cache.RefusedFromCache);
    }

    [TestMethod]
    public void ARefusal_ExpiresAndTheDestinationIsAskedAboutAgain()
    {
        _inner.FailOpens = true;

        Open();

        _clock.Advance(TimeSpan.FromSeconds(11));
        _inner.FailOpens = false;
        Open();

        Assert.AreEqual(2, _inner.OpenRequests, "a service can come up behind the server; the verdict must age out");
        Assert.AreEqual(1, _opened);
    }

    [TestMethod]
    public void TheVerdictIsPerDestination_NotPerAddress()
    {
        _inner.FailOpens = true;

        Open(port: 443);
        _inner.FailOpens = false;
        Open(port: 80);

        Assert.AreEqual(2, _inner.OpenRequests, "another port on the same host is a different question");
        Assert.AreEqual(1, _opened);
    }

    [TestMethod]
    public void ASuccessfulOpen_PassesStraightThrough()
    {
        Open();

        Assert.AreEqual(1, _opened);
        Assert.AreEqual(0, _failed);
    }
}
