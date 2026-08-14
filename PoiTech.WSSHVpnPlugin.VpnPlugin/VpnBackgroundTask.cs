using System;
using Windows.ApplicationModel.Background;
using Windows.ApplicationModel.Core;
using Windows.Networking.Vpn;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Entry point the VPN platform activates. Declared in the package manifest as a
/// <c>windows.backgroundTasks</c> extension with a <c>vpnClient</c> task type.
/// </summary>
/// <remarks>
/// The platform activates this task once per plug-in event (connect, encapsulate, decapsulate,
/// keep-alive, disconnect) and hands the event off through
/// <see cref="VpnChannel.ProcessEventAsync(object, object)"/>. Every activation must hand the
/// platform the <em>same</em> <see cref="IVpnPlugIn"/> instance, because the plug-in carries
/// state across events — a partially reassembled packet, the live SSH session, and so on. The
/// instance is therefore parked in <see cref="CoreApplication.Properties"/>, which outlives an
/// individual task activation but not the host process.
/// </remarks>
public sealed class VpnBackgroundTask : IBackgroundTask
{
    private const string PlugInPropertyKey = "PoiTech.WSSHVpnPlugin.PlugIn";

    /// <inheritdoc/>
    public void Run(IBackgroundTaskInstance taskInstance)
    {
        ArgumentNullException.ThrowIfNull(taskInstance);

        var deferral = taskInstance.GetDeferral();
        try
        {
            VpnChannel.ProcessEventAsync(GetOrCreatePlugIn(), taskInstance.TriggerDetails);
        }
        catch (Exception ex)
        {
            // Letting an exception escape would tear down the background task host and leave the
            // platform without a response to the event it raised.
            PluginLog.Error("Unhandled exception while processing a VPN event", ex);
        }
        finally
        {
            deferral.Complete();
        }
    }

    private static IVpnPlugIn GetOrCreatePlugIn()
    {
        var properties = CoreApplication.Properties;
        lock (properties)
        {
            if (properties.TryGetValue(PlugInPropertyKey, out var existing) && existing is IVpnPlugIn plugIn)
            {
                return plugIn;
            }

            PluginLog.Info($"Creating plug-in instance (log: {PluginLog.LogPath})");
            var created = new SSHVpnPlugin();
            properties[PlugInPropertyKey] = created;
            return created;
        }
    }
}
