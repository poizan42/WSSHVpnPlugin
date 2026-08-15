using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;

using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.Net.Tests;

/// <summary>
/// Fakes for the stack's seams, so a whole connection can be driven with no SSH, no platform, no
/// sockets and no threads.
/// </summary>
internal sealed class FakeChannel : IByteChannel
{
    private readonly List<byte> _received = new();

    /// <summary>Everything the stack has sent onward, in order.</summary>
    public List<byte> Sent { get; } = new();

    public bool IsOpen { get; set; } = true;

    public bool IsPeerEof { get; set; }

    public bool Disposed { get; private set; }

    /// <summary>How many bytes a send may take, or -1 for all of them.</summary>
    public int SendLimit { get; set; } = -1;

    /// <summary>Set when the stack signalled that it will send no more.</summary>
    public bool EofSent { get; private set; }

    public int WindowCreditFlushes { get; private set; }

    /// <summary>Queues bytes as though they had arrived from the far end.</summary>
    public void ReceiveFromPeer(params byte[] data)
    {
        _received.AddRange(data);
    }

    public bool TryRead(out ArraySegment<byte> data)
    {
        if (_received.Count == 0)
        {
            data = default;
            return false;
        }

        data = new ArraySegment<byte>(_received.ToArray());
        return true;
    }

    public bool Advance(int count)
    {
        _received.RemoveRange(0, count);

        // Pretend a flush is due once half a notional window has gone by.
        return count >= 512;
    }

    public void FlushWindowCredit()
    {
        WindowCreditFlushes++;
    }

    public ByteChannelSendResult TrySend(byte[] data, int offset, int count, out int written)
    {
        if (!IsOpen)
        {
            written = 0;
            return ByteChannelSendResult.Closed;
        }

        written = SendLimit < 0 ? count : Math.Min(SendLimit, count);
        Sent.AddRange(new ArraySegment<byte>(data, offset, written));

        return written == count ? ByteChannelSendResult.Written : ByteChannelSendResult.Full;
    }

    public void SendEof()
    {
        EofSent = true;
    }

    public void Dispose()
    {
        Disposed = true;
    }
}

/// <summary>
/// Hands out <see cref="FakeChannel"/>s, either immediately or when the test says so.
/// </summary>
internal sealed class FakeChannelFactory : IByteChannelFactory
{
    /// <summary>
    /// Deferred opens, oldest first. A queue rather than a single slot because more than one can be
    /// outstanding at once - which is the case a leaked channel hides in.
    /// </summary>
    private readonly Queue<(Action<IByteChannel> OnOpened, Action OnFailed)> _pending = new();

    /// <summary>Set to open channels as soon as they are asked for.</summary>
    public bool OpenImmediately { get; set; } = true;

    /// <summary>Set to fail every open.</summary>
    public bool FailOpens { get; set; }

    public FakeChannel? Last { get; private set; }

    public int OpenRequests { get; private set; }

    public uint LastAddress { get; private set; }

    public ushort LastPort { get; private set; }

    public void BeginOpen(uint address, ushort port, Action<IByteChannel> onOpened, Action onFailed)
    {
        OpenRequests++;
        LastAddress = address;
        LastPort = port;

        if (FailOpens)
        {
            onFailed();
            return;
        }

        if (OpenImmediately)
        {
            Complete(onOpened);
            return;
        }

        _pending.Enqueue((onOpened, onFailed));
    }

    /// <summary>Gets how many deferred opens are waiting.</summary>
    public int PendingOpens => _pending.Count;

    /// <summary>Completes the oldest open that was deferred, as a real one would be.</summary>
    public FakeChannel CompleteOpen()
    {
        if (!_pending.TryDequeue(out var pending))
        {
            throw new InvalidOperationException("No open is pending.");
        }

        return Complete(pending.OnOpened);
    }

    /// <summary>Fails the oldest open that was deferred.</summary>
    public void FailOpen()
    {
        if (!_pending.TryDequeue(out var pending))
        {
            throw new InvalidOperationException("No open is pending.");
        }

        pending.OnFailed();
    }

    private FakeChannel Complete(Action<IByteChannel> onOpened)
    {
        var channel = new FakeChannel();
        Last = channel;
        onOpened(channel);
        return channel;
    }
}

/// <summary>
/// Collects the packets the stack synthesises.
/// </summary>
internal sealed class FakeSink : IPacketSink
{
    public List<byte[]> Packets { get; } = new();

    /// <summary>Set to refuse packets, as a full buffer pool would.</summary>
    public bool Full { get; set; }

    public bool CanAccept => !Full;

    public bool TryWrite(ReadOnlySpan<byte> packet)
    {
        if (Full)
        {
            return false;
        }

        Packets.Add(packet.ToArray());
        return true;
    }

    /// <summary>Reads back the last packet as an IPv4 and TCP pair.</summary>
    public (uint Source, uint Destination, ushort SourcePort, ushort DestinationPort, uint Seq, uint Ack, TcpFlags Flags, byte[] Payload) Last()
    {
        return At(Packets.Count - 1);
    }

    public (uint Source, uint Destination, ushort SourcePort, ushort DestinationPort, uint Seq, uint Ack, TcpFlags Flags, byte[] Payload) At(int index)
    {
        var bytes = Packets[index];

        if (!Ipv4Packet.TryParse(bytes, out var ip) || !TcpSegment.TryParse(ip.Payload, out var tcp))
        {
            throw new InvalidOperationException("The stack produced something that is not TCP over IPv4.");
        }

        return (ip.Source, ip.Destination, tcp.SourcePort, tcp.DestinationPort,
                tcp.SequenceNumber, tcp.AcknowledgementNumber, tcp.Flags, tcp.Payload.ToArray());
    }
}

/// <summary>
/// Builds the packets a test pretends the operating system sent.
/// </summary>
internal static class Packets
{
    public static uint Address(string dotted)
    {
        return BinaryPrimitives.ReadUInt32BigEndian(IPAddress.Parse(dotted).GetAddressBytes());
    }

    public static byte[] Tcp(
        uint source,
        uint destination,
        ushort sourcePort,
        ushort destinationPort,
        uint sequenceNumber,
        uint acknowledgementNumber,
        TcpFlags flags,
        ReadOnlySpan<byte> payload = default,
        ushort? mss = null,
        ushort windowSize = 65535)
    {
        var buffer = new byte[1500];
        var tcpStart = Ipv4Packet.MinimumHeaderLength;
        var headerLength = TcpSegment.MinimumHeaderLength + (mss.HasValue ? 4 : 0);

        payload.CopyTo(buffer.AsSpan(tcpStart + headerLength));

        var tcpLength = TcpSegment.Write(
            buffer.AsSpan(tcpStart),
            source,
            destination,
            sourcePort,
            destinationPort,
            sequenceNumber,
            acknowledgementNumber,
            flags,
            windowSize,
            payload.Length,
            mss);

        var total = Ipv4Packet.Write(buffer, IpProtocol.Tcp, source, destination, tcpLength);
        return buffer.AsSpan(0, total).ToArray();
    }
}

/// <summary>
/// A clock the test moves by hand.
/// </summary>
/// <remarks>
/// Delayed acknowledgements and retransmission timeouts are measured in tens and hundreds of
/// milliseconds. A suite that waited for them would take minutes and still be flaky.
/// </remarks>
internal sealed class FakeClock : IStackClock
{
    public TimeSpan Now { get; private set; }

    public void Advance(TimeSpan by)
    {
        Now += by;
    }
}
