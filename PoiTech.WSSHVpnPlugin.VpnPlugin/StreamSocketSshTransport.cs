using System;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Renci.SshNet.Common;
using Renci.SshNet.Connection;
using Windows.Networking;
using Windows.Networking.Sockets;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Carries an SSH session over a WinRT <see cref="StreamSocket"/>.
/// </summary>
/// <remarks>
/// <para>
/// SSH.NET normally drives a <see cref="System.Net.Sockets.Socket"/>, which is no use here: the VPN
/// platform has to be handed the socket carrying the SSH connection so it can keep that traffic out
/// of the tunnel it installs, and it only understands WinRT socket objects. The
/// <see cref="StreamSocket"/> this owns is what gets passed to
/// <see cref="Windows.Networking.Vpn.VpnChannel.StartWithMainTransport"/>.
/// </para>
/// <para>
/// Both adapters are created unbuffered. The session does its own framing and buffering, and a
/// buffered writer would sit on outgoing SSH packets rather than sending them.
/// </para>
/// <para>
/// The blocking members wait on the underlying task. That is safe here only because no session
/// thread carries a synchronization context.
/// </para>
/// </remarks>
internal sealed class StreamSocketSshTransport : SshTransport
{
    private readonly StreamSocket _socket;
    private readonly Stream _input;
    private readonly Stream _output;

    private int _disposed;
    private int _shutdown;
    private bool _isConnected;

    private StreamSocketSshTransport(StreamSocket socket)
    {
        _socket = socket;
        _input = socket.InputStream.AsStreamForRead(bufferSize: 0);
        _output = socket.OutputStream.AsStreamForWrite(bufferSize: 0);
        _isConnected = true;
    }

    /// <summary>
    /// Gets the underlying socket, to be handed to the VPN platform as the outer tunnel transport.
    /// </summary>
    public StreamSocket Socket => _socket;

    /// <inheritdoc/>
    public override bool IsConnected => _isConnected && Volatile.Read(ref _disposed) == 0;

    /// <summary>
    /// Connects to the specified SSH endpoint.
    /// </summary>
    public static async Task<StreamSocketSshTransport> ConnectAsync(
        string host,
        int port,
        CancellationToken cancellationToken)
    {
        var socket = new StreamSocket();
        try
        {
            socket.Control.NoDelay = true;
            socket.Control.KeepAlive = true;

            await socket.ConnectAsync(new HostName(host), port.ToString(CultureInfo.InvariantCulture))
                        .AsTask(cancellationToken)
                        .ConfigureAwait(false);

            return new StreamSocketSshTransport(socket);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <inheritdoc/>
    public override int Read(byte[] buffer, int offset, int count, TimeSpan timeout)
    {
        if (timeout == Timeout.InfiniteTimeSpan)
        {
            return Complete(() => _input.Read(buffer, offset, count));
        }

        using var cts = new CancellationTokenSource(timeout);
        try
        {
            return Complete(() => _input.ReadAsync(buffer.AsMemory(offset, count), cts.Token)
                                        .AsTask()
                                        .GetAwaiter()
                                        .GetResult());
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            throw new SshOperationTimeoutException(string.Format(
                CultureInfo.InvariantCulture,
                "Socket read operation has timed out after {0:F0} milliseconds.",
                timeout.TotalMilliseconds));
        }
    }

    /// <inheritdoc/>
    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        int read;
        try
        {
            read = await _input.ReadAsync(buffer.AsMemory(offset, count), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsExpectedDuringTeardown(ex))
        {
            _isConnected = false;
            return 0;
        }

        if (read == 0)
        {
            _isConnected = false;
        }

        return read;
    }

    /// <inheritdoc/>
    public override void Write(byte[] buffer, int offset, int count)
    {
        _output.Write(buffer, offset, count);
    }

    /// <inheritdoc/>
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return _output.WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    /// <inheritdoc/>
    public override void Shutdown()
    {
        _isConnected = false;
        _ = Interlocked.Exchange(ref _shutdown, 1);

        // StreamSocket has no half-close; cancelling pending I/O is what interrupts the blocked
        // read on the message listener thread.
        try
        {
            _ = _socket.CancelIOAsync().AsTask().Wait(TimeSpan.FromSeconds(1));
        }
        catch (Exception ex)
        {
            PluginLog.Error("Failed to cancel socket I/O during shutdown", ex);
        }
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (!disposing || Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _isConnected = false;
        _ = Interlocked.Exchange(ref _shutdown, 1);

        _input.Dispose();
        _output.Dispose();
        _socket.Dispose();
    }

    /// <summary>
    /// Runs a blocking read, reporting a close rather than an error when the failure is the result
    /// of our own teardown.
    /// </summary>
    private int Complete(Func<int> read)
    {
        int bytesRead;
        try
        {
            bytesRead = read();
        }
        catch (Exception ex) when (IsExpectedDuringTeardown(ex))
        {
            _isConnected = false;
            return 0;
        }

        if (bytesRead == 0)
        {
            _isConnected = false;
        }

        return bytesRead;
    }

    /// <summary>
    /// Determines whether an exception is the expected consequence of <see cref="Shutdown"/> or
    /// <see cref="Dispose(bool)"/>, in which case the session should see a clean close instead of an
    /// error. Anything else is a genuine failure and is left to propagate.
    /// </summary>
    private bool IsExpectedDuringTeardown(Exception exception)
    {
        if (Volatile.Read(ref _shutdown) == 0)
        {
            return false;
        }

        return exception is IOException or ObjectDisposedException or OperationCanceledException;
    }
}
