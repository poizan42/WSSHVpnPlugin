using System;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Windows.ApplicationModel;
using Windows.ApplicationModel.Background;
using Windows.Networking.Vpn;
using Windows.Storage;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;

namespace PoiTech.WSSHVpnPlugin.App;

/// <summary>
/// Provisions and drives the VPN profile that points at this package's plug-in.
/// </summary>
/// <remarks>
/// There is no system UI for creating a plug-in VPN profile — the owning app has to create it
/// through <see cref="VpnManagementAgent"/>. Once the profile exists it shows up in Settings
/// like any other VPN connection.
/// </remarks>
public sealed partial class MainPage : Page
{
    private readonly VpnManagementAgent _agent = new();

    public MainPage()
    {
        InitializeComponent();
        LoadSettings();
    }

    /// <summary>
    /// Restores the form from local settings.
    /// </summary>
    /// <remarks>
    /// The values are per-machine and deliberately not committed anywhere: this repository is
    /// public, and the host, user name and key path are not ours to publish.
    /// </remarks>
    private void LoadSettings()
    {
        var values = ApplicationData.Current.LocalSettings.Values;

        foreach (var (box, key) in SettingsBoxes())
        {
            if (values.ContainsKey(key) && values[key] is string text)
            {
                box.Text = text;
            }
        }

        SpikeProbeCheck.IsChecked = values.ContainsKey("SpikeProbe") && values["SpikeProbe"] is true;
        RemoteTransportCheck.IsChecked = values.ContainsKey("RemoteDummyTransport") && values["RemoteDummyTransport"] is true;
        AssignIPv6Check.IsChecked = values.ContainsKey("AssignIPv6") && values["AssignIPv6"] is true;
        LargeFrameCheck.IsChecked = values.ContainsKey("LargeFrameSize") && values["LargeFrameSize"] is true;
    }

    private void SaveSettings()
    {
        var values = ApplicationData.Current.LocalSettings.Values;

        foreach (var (box, key) in SettingsBoxes())
        {
            values[key] = box.Text;
        }

        values["SpikeProbe"] = SpikeProbeCheck.IsChecked == true;
        values["RemoteDummyTransport"] = RemoteTransportCheck.IsChecked == true;
        values["AssignIPv6"] = AssignIPv6Check.IsChecked == true;
        values["LargeFrameSize"] = LargeFrameCheck.IsChecked == true;
    }

    private (TextBox Box, string Key)[] SettingsBoxes()
    {
        return new[]
        {
            (ProfileNameBox, "ProfileName"),
            (HostBox, "Host"),
            (PortBox, "Port"),
            (UserNameBox, "UserName"),
            (PrivateKeyPathBox, "PrivateKeyPath"),
            (FingerprintBox, "HostKeyFingerprint"),
            (ClientAddressBox, "ClientIPv4"),
            (NetworkAdapterBox, "NetworkAdapter"),
            (TracerBox, "TracerDestination"),
            (DnsBox, "DnsServers"),
            (StartDelayBox, "StartDelaySeconds"),
        };
    }

    private async void OnSaveProfileClick(object sender, RoutedEventArgs e)
    {
        await RunAsync("Save profile", async () =>
        {
            var profile = BuildProfile();

            // Add refuses when a profile of this name already exists, so fall back to update.
            // Getting this wrong is quiet and expensive: the save reports a failure, the old
            // profile stays in place, and the next Connect exercises the previous settings.
            var status = await _agent.AddProfileFromObjectAsync(profile);
            if (status != VpnManagementErrorStatus.Ok)
            {
                Log($"AddProfileFromObjectAsync: {status}; updating the existing profile instead");
                status = await _agent.UpdateProfileFromObjectAsync(profile);
                Log($"UpdateProfileFromObjectAsync: {status}");
                return;
            }

            Log($"AddProfileFromObjectAsync: {status}");
        });
    }

    private async void OnConnectClick(object sender, RoutedEventArgs e)
    {
        await RunAsync("Connect", async () =>
        {
            await EnsureBackgroundAccessAsync();

            var status = await _agent.ConnectProfileAsync(BuildProfile());
            Log($"ConnectProfileAsync: {status}");
        });
    }

    /// <summary>
    /// Asks for background execution access before connecting.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Associating a transport with the VPN channel registers it as a <c>ControlChannelTrigger</c>,
    /// and <c>ControlChannelTrigger</c> is documented as requiring this call first. The plug-in
    /// itself cannot make it — it runs in a background task, and the access being requested is the
    /// right to run there — so the foreground app has to, and it applies to the whole package.
    /// </para>
    /// <para>
    /// Worth logging rather than firing and forgetting: <c>StartWithMainTransport</c> currently fails
    /// with <c>E_OUTOFMEMORY</c>, which is traced to the trigger broker refusing over RPC, and a
    /// refused background quota is a candidate explanation for a resource error of that shape.
    /// </para>
    /// </remarks>
    private async Task EnsureBackgroundAccessAsync()
    {
        try
        {
            var before = BackgroundExecutionManager.GetAccessStatus();
            var after = await BackgroundExecutionManager.RequestAccessAsync();
            Log($"Background access: {before} -> {after}");
        }
        catch (Exception ex)
        {
            Log($"Background access request failed: {ex.Message}");
        }
    }

    private async void OnDisconnectClick(object sender, RoutedEventArgs e)
    {
        await RunAsync("Disconnect", async () =>
        {
            var status = await _agent.DisconnectProfileAsync(BuildProfile());
            Log($"DisconnectProfileAsync: {status}");
        });
    }

    /// <summary>
    /// Runs the loopback datagram exchange the plug-in's outer tunnel transport depends on.
    /// </summary>
    /// <remarks>
    /// Here rather than in the plug-in because it needs no VPN channel: the app container check is
    /// on the package, which is the same one. If this fails, nothing about the tunnel can work, and
    /// finding that out costs a click instead of an activation.
    /// </remarks>
    private async void OnTestLoopbackClick(object sender, RoutedEventArgs e)
    {
        await RunAsync("Test loopback", async () => Log(await LoopbackProbe.RunAsync()));
    }

    /// <summary>
    /// Drives the control channel trigger directly, without a VPN channel.
    /// </summary>
    /// <remarks>
    /// The trigger is the part that actually fails, and unlike a VPN channel it can be created and
    /// discarded repeatedly — so this is where the failure can be narrowed down without a deploy and
    /// an activation per attempt.
    /// </remarks>
    private async void OnTestCctClick(object sender, RoutedEventArgs e)
    {
        await RunAsync("Test CCT", async () =>
        {
            // The socket IOCTL first: that is the call the VPN platform actually fails on, and
            // unlike the trigger it is a plain socket operation we can issue directly.
            Log(TransportSettingProbe.Run());
            Log(await CctProbe.RunAsync());
        });
    }

    /// <summary>
    /// Dumps what the VPN platform actually has registered.
    /// </summary>
    /// <remarks>
    /// Worth having as a button rather than reasoning about it: whether a profile exists, and how one
    /// created here differs from one created in Settings, has been guessed at repeatedly. This is the
    /// authoritative view, and it has to run inside the package to see the package's own profiles.
    /// </remarks>
    private async void OnListProfilesClick(object sender, RoutedEventArgs e)
    {
        await RunAsync("List profiles", async () =>
        {
            var profiles = await _agent.GetProfilesAsync();
            Log($"GetProfilesAsync: {profiles.Count} profile(s)");

            foreach (var profile in profiles)
            {
                if (profile is VpnPlugInProfile plugIn)
                {
                    var servers = string.Join(", ", plugIn.ServerUris);
                    Log($"  plug-in '{plugIn.ProfileName}' pkg={plugIn.VpnPluginPackageFamilyName} "
                        + $"servers=[{servers}] alwaysOn={plugIn.AlwaysOn} "
                        + $"customConfig={plugIn.CustomConfiguration?.Length ?? 0} chars");

                    if (plugIn.CustomConfiguration is { Length: > 0 } config)
                    {
                        Log($"    config starts: {config[..Math.Min(60, config.Length)]}");
                    }
                }
                else if (profile is VpnNativeProfile native)
                {
                    Log($"  native  '{native.ProfileName}' type={native.NativeProtocolType}");
                }
                else
                {
                    Log($"  other   '{profile.ProfileName}' ({profile.GetType().Name})");
                }
            }
        });
    }

    private async void OnDeleteProfileClick(object sender, RoutedEventArgs e)
    {
        await RunAsync("Delete profile", async () =>
        {
            var status = await _agent.DeleteProfileAsync(BuildProfile());
            Log($"DeleteProfileAsync: {status}");
        });
    }

    private VpnPlugInProfile BuildProfile()
    {
        SaveSettings();

        var host = HostBox.Text.Trim();
        if (host.Length == 0)
        {
            throw new InvalidOperationException("Enter the SSH server host name.");
        }

        if (!uint.TryParse(PortBox.Text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var port))
        {
            throw new InvalidOperationException("The port must be a number.");
        }

        var profileName = ProfileNameBox.Text.Trim();
        if (profileName.Length == 0)
        {
            throw new InvalidOperationException("Enter a profile name.");
        }

        var profile = new VpnPlugInProfile
        {
            ProfileName = profileName,
            AlwaysOn = false,
            RememberCredentials = true,

            // Points the platform at the plug-in inside this package.
            VpnPluginPackageFamilyName = Package.Current.Id.FamilyName,

            CustomConfiguration = BuildCustomConfiguration(port),
        };

        // The platform hands these to the plug-in as VpnChannelConfiguration.ServerHostNameList,
        // which it builds by pulling the host out of each URI. The scheme has to be one WinRT's own
        // URI parser recognises — with "ssh://" it fails to find a host at all and reading
        // ServerHostNameList throws ArgumentException("hostName"). The scheme is otherwise
        // meaningless here; the port the plug-in dials comes from <Port> in the custom config.
        profile.ServerUris.Add(new Uri($"https://{host}"));

        return profile;
    }

    private string BuildCustomConfiguration(uint port)
    {
        var root = new XElement(
            "SshVpnConfiguration",
            // Carried here rather than relied upon from ServerUris: reading the platform's
            // ServerHostNameList throws for this profile. See SshVpnConfiguration.TryGetFirstServerHost.
            new XElement("Host", HostBox.Text.Trim()),
            new XElement("Port", port.ToString(CultureInfo.InvariantCulture)),
            new XElement("ClientIPv4", ClientAddressBox.Text.Trim()));

        var userName = UserNameBox.Text.Trim();
        if (userName.Length > 0)
        {
            root.Add(new XElement("UserName", userName));
        }

        var networkAdapter = NetworkAdapterBox.Text.Trim();
        if (networkAdapter.Length > 0)
        {
            root.Add(new XElement("NetworkAdapter", networkAdapter));
        }

        var tracerDestination = TracerBox.Text.Trim();
        if (tracerDestination.Length > 0)
        {
            root.Add(new XElement("TracerDestination", tracerDestination));
        }

        var privateKeyPath = PrivateKeyPathBox.Text.Trim();
        if (privateKeyPath.Length > 0)
        {
            root.Add(new XElement("PrivateKeyPath", privateKeyPath));
        }

        var fingerprint = FingerprintBox.Text.Trim();
        if (fingerprint.Length > 0)
        {
            root.Add(new XElement("HostKeyFingerprint", fingerprint));
        }

        if (SpikeProbeCheck.IsChecked == true)
        {
            root.Add(new XElement("SpikeProbe", "true"));
        }

        if (RemoteTransportCheck.IsChecked == true)
        {
            root.Add(new XElement("RemoteDummyTransport", "true"));
        }

        if (AssignIPv6Check.IsChecked == true)
        {
            root.Add(new XElement("AssignIPv6", "true"));
        }

        if (LargeFrameCheck.IsChecked == true)
        {
            root.Add(new XElement("LargeFrameSize", "true"));
        }

        var startDelay = StartDelayBox.Text.Trim();
        if (startDelay.Length > 0 && startDelay != "0")
        {
            root.Add(new XElement("StartDelaySeconds", startDelay));
        }

        foreach (var dns in DnsBox.Text.Split(','))
        {
            var trimmed = dns.Trim();
            if (trimmed.Length > 0)
            {
                root.Add(new XElement("DnsServer", trimmed));
            }
        }

        return root.ToString(SaveOptions.DisableFormatting);
    }

    private async Task RunAsync(string operation, Func<Task> action)
    {
        SetBusy(true);
        try
        {
            await action();
        }
        catch (Exception ex)
        {
            Log($"{operation} failed: {ex.Message}");
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void SetBusy(bool busy)
    {
        SaveButton.IsEnabled = !busy;
        ConnectButton.IsEnabled = !busy;
        DisconnectButton.IsEnabled = !busy;
        DeleteButton.IsEnabled = !busy;
        LoopbackButton.IsEnabled = !busy;
        CctButton.IsEnabled = !busy;
        ListButton.IsEnabled = !busy;
    }

    private void Log(string message)
    {
        var line = new StringBuilder()
            .Append(DateTimeOffset.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture))
            .Append("  ")
            .Append(message)
            .AppendLine()
            .ToString();

        StatusText.Text += line;
    }
}
