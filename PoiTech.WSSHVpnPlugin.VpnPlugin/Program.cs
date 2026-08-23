using System;
using Windows.ApplicationModel.Core;
using Windows.Foundation;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// The plug-in's own host process.
/// </summary>
/// <remarks>
/// <para>
/// A <c>vpnClient</c> background task must name its own host executable: leaving <c>Executable</c>
/// off the extension so that <c>backgroundtaskhost.exe</c> would host it fails registration with
/// <c>0x80080204</c>, "a task of this type requires a custom background task host". So the plug-in
/// supplies one, and this is it.
/// </para>
/// <para>
/// What matters is what this does <em>not</em> do: start a XAML application. Naming the UI app's
/// executable as the host is tempting, since Native AOT will link the component into it and
/// re-export its activation factory — and fatal, because it puts the VPN host inside a XAML
/// application's process. When the platform suspends that application,
/// <c>DXamlCore::OnAfterAppSuspend</c> calls <c>GC.Collect()</c> inside the tunnel's process, and
/// that collection deadlocks against a ComWrappers callout: a class constructor runs inside the
/// collection, allocates, and waits for the collection it is already inside. Windows then logs
/// "stopped interacting with Windows and was closed" and kills the host about a minute after every
/// connect. See the hang notes in CLAUDE.md. A background host has no window to show and nothing to
/// suspend.
/// </para>
/// </remarks>
internal static class Program
{
    private static void Main()
    {
        // Hands the platform the activation factories this executable exports, then runs the loop
        // that services them. This is what Application.Start does, minus everything XAML.
        CoreApplication.RunWithActivationFactories(new ActivationFactorySource());
    }
}

/// <summary>
/// Resolves the activation factories this executable exports.
/// </summary>
/// <remarks>
/// Public, and deliberately so, against this assembly's rule that only <c>SSHVpnPlugin</c> and
/// <c>VpnBackgroundTask</c> are public. The platform calls this through COM, so CsWinRT has to
/// generate a callable wrapper for it, and it only does that for authored - that is, public - types.
/// As a private nested class it compiled and then failed at runtime with <c>E_NOINTERFACE</c> from
/// <c>CreateCCWForObjectForABI</c>, taking the host down before it could log anything.
/// </remarks>
public sealed class ActivationFactorySource : IGetActivationFactory
{
    /// <summary>
    /// Returns the activation factory for a class this executable exports.
    /// </summary>
    /// <param name="activatableClassId">The runtime class name being activated.</param>
    /// <returns>The factory.</returns>
    public object GetActivationFactory(string activatableClassId)
    {
        return WinRT.Module.GetActivationFactory(activatableClassId);
    }
}
