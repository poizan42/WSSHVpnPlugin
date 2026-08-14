using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Renci.SshNet.Common;
using Renci.SshNet.Connection;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;

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
/// <see cref="StreamSocket"/> is async-only, while the session reads on a dedicated thread and
/// writes synchronously from others. The blocking members below bridge that by waiting on the
/// underlying task; that is safe here because no member ever runs on a thread carrying a
/// synchronization context.
/// </para>
/// </remarks>
internal sealed class StreamSocketSshTransport : SshTransport
{
    private readonly StreamSocket _socket;
    private readonly DataReader _reader;
    private readonly DataWriter _writer;

    /// <summary>
    /// Scratch space for <see cref="DataReader.ReadBytes(byte[])"/>, which fills the whole array and
    /// so needs one sized exactly to the read. The session reads a small set of recurring sizes, so
    /// this is reallocated rarely.
    /// </summary>
    private byte[] _scratch = Array.Empty<byte>();

    private int _disposed;
    private bool _isConnected;

    private StreamSocketSshTransport(StreamSocket socket)
    {
        _socket = socket;
        _reader = new DataReader(socket.InputStream)
        {
            // Return whatever has arrived rather than waiting for the full count, which is the
            // semantic the session's read loop expects from a socket.
            InputStreamOptions = InputStreamOptions.Partial,
        };
        _writer = new DataWriter(socket.OutputStream);
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
            return ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
        }

        using var cts = new CancellationTokenSource(timeout);
        try
        {
            return ReadAsync(buffer, offset, count, cts.Token).GetAwaiter().GetResult();
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
        if (count == 0)
        {
            return 0;
        }

        if (_reader.UnconsumedBufferLength == 0)
        {
            uint loaded;
            try
            {
                loaded = await _reader.LoadAsync((uint)count).AsTask(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is ObjectDisposedException || IsSocketClosed(ex))
            {
                _isConnected = false;
                return 0;
            }

            if (loaded == 0)
            {
                // The server closed the connection.
                _isConnected = false;
                return 0;
            }
        }

        var toRead = (int)Math.Min((uint)count, _reader.UnconsumedBufferLength);

        if (_scratch.Length != toRead)
        {
            _scratch = new byte[toRead];
        }

        _reader.ReadBytes(_scratch);
        System.Buffer.BlockCopy(_scratch, 0, buffer, offset, toRead);
        return toRead;
    }

    /// <inheritdoc/>
    public override void Write(byte[] buffer, int offset, int count)
    {
        WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        // DataWriter has no offset overload, so hand it exactly the span being sent.
        var slice = new byte[count];
        System.Buffer.BlockCopy(buffer, offset, slice, 0, count);

        _writer.WriteBytes(slice);
        _ = await _writer.StoreAsync().AsTask(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public override void Shutdown()
    {
        _isConnected = false;

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

        // Detach first: disposing a DataReader/DataWriter otherwise closes the socket's streams
        // out from under the socket itself.
        try
        {
            _ = _reader.DetachStream();
            _reader.Dispose();
            _ = _writer.DetachStream();
            _writer.Dispose();
        }
        catch (Exception ex)
        {
            PluginLog.Error("Failed to detach socket streams", ex);
        }

        _socket.Dispose();
    }

    private static bool IsSocketClosed(Exception exception)
    {
        return SocketError.GetStatus(exception.HResult) is SocketErrorStatus.ConnectionResetByPeer
            or SocketErrorStatus.ConnectionTimedOut
            or SocketErrorStatus.OperationAborted
            or SocketErrorStatus.SoftwareCausedConnectionAbort;
    }
}
