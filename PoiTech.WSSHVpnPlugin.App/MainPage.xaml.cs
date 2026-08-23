using System;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Windows.ApplicationModel;
using Windows.Networking.Vpn;
using Windows.Storage;
using Windows.Storage.AccessCache;
using Windows.Storage.Pickers;
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

    private const string PrivateKeyTokenSetting = "PrivateKeyToken";

    /// <summary>
    /// The FutureAccessList token for the picked key, which is what the plug-in redeems to read it.
    /// </summary>
    private string _privateKeyToken = string.Empty;

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

        // Not shown in the form: it is an opaque handle, and the file name above is what identifies
        // the key to the user.
        if (values.ContainsKey(PrivateKeyTokenSetting) && values[PrivateKeyTokenSetting] is string token)
        {
            _privateKeyToken = token;
        }

    }

    private void SaveSettings()
    {
        var values = ApplicationData.Current.LocalSettings.Values;

        foreach (var (box, key) in SettingsBoxes())
        {
            values[key] = box.Text;
        }

        values[PrivateKeyTokenSetting] = _privateKeyToken;

    }

    private (TextBox Box, string Key)[] SettingsBoxes()
    {
        return new[]
        {
            (ProfileNameBox, "ProfileName"),
            (HostBox, "Host"),
            (PortBox, "Port"),
            (UserNameBox, "UserName"),
            (FingerprintBox, "HostKeyFingerprint"),
            (ClientAddressBox, "ClientIPv4"),
            (ClientIPv6Box, "ClientIPv6"),
            (ExcludeRoutesBox, "ExcludeRoutes"),
            (DnsBox, "DnsServers"),
            (KeyFileBox, "PrivateKeyFile"),
            (MtuBox, "Mtu"),
            (OpenTimeoutBox, "OpenTimeoutSeconds"),
            (StartDelayBox, "StartDelaySeconds"),
        };
    }

    /// <summary>
    /// Picks the private key and keeps durable access to it, which is what lets the package declare
    /// no file-system capability.
    /// </summary>
    /// <remarks>
    /// The FutureAccessList entry keeps the picked file readable across restarts, and the token is a
    /// string, so it travels in the profile like any other setting. Only the plug-in reads the key;
    /// this process just picks it.
    /// </remarks>
    private async void OnPickKeyClick(object sender, RoutedEventArgs e)
    {
        await RunAsync("Pick key file", async () =>
        {
            var picker = new FileOpenPicker { SuggestedStartLocation = PickerLocationId.DocumentsLibrary };

            // SSH keys conventionally have no extension, and the picker rejects an empty filter list.
            picker.FileTypeFilter.Add("*");

            var file = await picker.PickSingleFileAsync();
            if (file is null)
            {
                Log("Pick key file: cancelled");
                return;
            }

            _privateKeyToken = StorageApplicationPermissions.FutureAccessList.Add(file);
            KeyFileBox.Text = file.Path;

            Log($"Key file: {file.Path}");
            Log("Save the profile to carry it to the plug-in.");
        });
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

    // No background-access request before connecting, deliberately. RequestAccessAsync was added
    // while StartWithMainTransport failed with E_OUTOFMEMORY and a refused background quota was one
    // of the candidate explanations - the real cause was the empty IPv6 address list - and it later
    // grew an AlwaysAllowed arm (plus the extendedBackgroundTaskTime capability) during the
    // activation-watchdog hunt, whose real cause was the doorbell flooding the delivery prolog. A
    // full-speed download with the app's background permission set to DeniedByUser then proved that
    // vpnClient activations bypass the user background-access policy entirely, so the request never
    // did anything at any point. See CLAUDE.md.
    private async void OnConnectClick(object sender, RoutedEventArgs e)
    {
        await RunAsync("Connect", async () =>
        {
            var status = await _agent.ConnectProfileAsync(BuildProfile());
            Log($"ConnectProfileAsync: {status}");
        });
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

        var clientIPv6 = ClientIPv6Box.Text.Trim();
        if (clientIPv6.Length > 0 && clientIPv6 != "fd00::2")
        {
            root.Add(new XElement("ClientIPv6", clientIPv6));
        }

        var userName = UserNameBox.Text.Trim();
        if (userName.Length > 0)
        {
            root.Add(new XElement("UserName", userName));
        }

        var fingerprint = FingerprintBox.Text.Trim();
        if (fingerprint.Length > 0)
        {
            root.Add(new XElement("HostKeyFingerprint", fingerprint));
        }

        var startDelay = StartDelayBox.Text.Trim();
        if (startDelay.Length > 0 && startDelay != "0")
        {
            root.Add(new XElement("StartDelaySeconds", startDelay));
        }

        if (_privateKeyToken.Length > 0)
        {
            root.Add(new XElement("PrivateKeyToken", _privateKeyToken));
        }

        // Only written when it differs from the plug-in's default, so an empty box means "default".
        // Raising this past 1400 goes against the documented maximum: it is worth about 14% on a
        // build that accepts it, and on one that does not the connect fails outright rather than
        // degrading, because the channel cannot be started twice. See SshVpnConfiguration.Mtu.
        var mtu = MtuBox.Text.Trim();
        if (mtu.Length > 0 && mtu != "1400")
        {
            root.Add(new XElement("Mtu", mtu));
        }

        // Only written when it differs from the plug-in's default, so an empty box means "default".
        var openTimeout = OpenTimeoutBox.Text.Trim();
        if (openTimeout.Length > 0 && openTimeout != "3")
        {
            root.Add(new XElement("OpenTimeoutSeconds", openTimeout));
        }

        foreach (var dns in DnsBox.Text.Split(','))
        {
            var trimmed = dns.Trim();
            if (trimmed.Length > 0)
            {
                root.Add(new XElement("DnsServer", trimmed));
            }
        }

        foreach (var route in ExcludeRoutesBox.Text.Split(','))
        {
            var trimmed = route.Trim();
            if (trimmed.Length > 0)
            {
                root.Add(new XElement("ExcludeRoute", trimmed));
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
