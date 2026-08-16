using System;
using System.Threading;
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

    /// <summary>
    /// How many activations to log before going quiet. Encapsulate runs at line rate, so this is a
    /// diagnostic budget rather than a running commentary.
    /// </summary>
    private const int ActivationLogBudget = 25;

    private static int _activations;

    /// <inheritdoc/>
    public void Run(IBackgroundTaskInstance taskInstance)
    {
        ArgumentNullException.ThrowIfNull(taskInstance);

        var deferral = taskInstance.GetDeferral();

        // A task that ignores this is terminated with its whole host: at line rate a decapsulate
        // event is always in flight, the platform cancels it to make room for its periodic
        // scheduling activation, and "did not complete in response to a cancel notification" is
        // the epitaph. The handlers poll the yield window and return promptly.
        taskInstance.Canceled += OnCanceled;

        var activation = 0;

        try
        {
            activation = LogActivation(taskInstance);
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
            taskInstance.Canceled -= OnCanceled;
            deferral.Complete();

            // The completion is the other half of the activation log: the platform kills hosts
            // over activations that never complete, and which ones those are is exactly what the
            // start lines alone cannot say.
            if (activation is > 0 and <= ActivationLogBudget)
            {
                PluginLog.Info($"Activation #{activation} completed ({taskInstance.InstanceId})");
            }
        }
    }

    private static void OnCanceled(IBackgroundTaskInstance sender, BackgroundTaskCancellationReason reason)
    {
        ActivationYield.Request();
        PluginLog.Info(
            $"The platform asked an activation to cancel ({reason}), instance {sender?.InstanceId.ToString() ?? "?"}; "
            + "in-flight handlers will yield");
    }

    /// <summary>
    /// Records that the platform activated us, and what it handed over.
    /// </summary>
    /// <remarks>
    /// Without this there is no way to tell "the platform never raised the event" from "it raised it
    /// and the plug-in returned early", which is exactly the question when no packet ever arrives.
    /// </remarks>
    private static int LogActivation(IBackgroundTaskInstance taskInstance)
    {
        var count = Interlocked.Increment(ref _activations);
        if (count > ActivationLogBudget)
        {
            return count;
        }

        var details = taskInstance.TriggerDetails;
        PluginLog.Info(
            $"Activation #{count} ({taskInstance.InstanceId}): trigger={taskInstance.Task?.Name ?? "?"}, "
            + $"details={details?.GetType().FullName ?? "null"}");

        return count;
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
