using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using Windows.Storage;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Minimal append-only logger. The plug-in runs inside the VPN background task host, where
/// there is no debugger attached most of the time, so a log file in the package's local
/// folder is the primary diagnostic channel.
/// </summary>
internal static class PluginLog
{
    private static readonly object Gate = new();
    private static string? logPath;

    public static void Info(string message) => Write("INFO", message);

    public static void Error(string message, Exception? exception = null)
    {
        Write("ERROR", exception is null ? message : $"{message}: {exception}");
    }

    /// <summary>
    /// Gets the full path of the log file, or <see langword="null"/> if it could not be determined.
    /// </summary>
    public static string? LogPath => logPath ??= TryResolveLogPath();

    private static void Write(string level, string message)
    {
        var line = string.Create(
            CultureInfo.InvariantCulture,
            $"{DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss.fff} [{level}] {message}");

        Debug.WriteLine(line);

        var path = LogPath;
        if (path is null)
        {
            return;
        }

        try
        {
            lock (Gate)
            {
                File.AppendAllText(path, line + Environment.NewLine, Encoding.UTF8);
            }
        }
        catch (IOException)
        {
            // Logging must never take down the tunnel.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static string? TryResolveLogPath()
    {
        try
        {
            return Path.Combine(ApplicationData.Current.LocalFolder.Path, "wsshvpn.log");
        }
        catch (Exception)
        {
            return null;
        }
    }
}
