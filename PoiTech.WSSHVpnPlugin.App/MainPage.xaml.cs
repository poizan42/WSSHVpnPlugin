using System;
using System.Globalization;
using System.IO;
using System.Linq;
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

using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.App;

/// <summary>
/// Edits the saved connections, and provisions the VPN profile that points at this package's
/// plug-in.
/// </summary>
/// <remarks>
/// The connection settings live in <see cref="ConnectionsFile.FileName"/> in the package's local
/// folder, keyed by server host, where the plug-in looks them up at connect. That is what makes a
/// profile added through Settings' own "Add VPN" dialog work — Settings can only name a server, and
/// the platform gives this app no way to write into a profile it did not create. Profiles created
/// here carry no configuration either; both kinds resolve through the same lookup.
/// </remarks>
public sealed partial class MainPage : Page
{
    private readonly VpnManagementAgent _agent = new();

    private const string PrivateKeyTokenSetting = "PrivateKeyToken";

    /// <summary>
    /// The FutureAccessList token for the picked key, which is what the plug-in redeems to read it.
    /// </summary>
    private string _privateKeyToken = string.Empty;

    /// <summary>The saved connections, as last read from or written to disk.</summary>
    private XElement _connections = ConnectionsFile.NewRoot();

    /// <summary>Suppresses selection handling while the form itself is being populated.</summary>
    private bool _loadingEntry;

    public MainPage()
    {
        InitializeComponent();
        LoadSettings();
        LoadConnections();
    }

    private static string ConnectionsPath
        => Path.Combine(ApplicationData.Current.LocalFolder.Path, ConnectionsFile.FileName);

    /// <summary>
    /// Restores the form from local settings.
    /// </summary>
    /// <remarks>
    /// The connections file is the store now; this survives as the migration source for installs
    /// that predate it — the prefilled form only has to be saved once to become an entry — and as
    /// the memory of the last-used host. The values are per-machine and deliberately not committed
    /// anywhere: this repository is public, and the host, user name and key path are not ours to
    /// publish.
    /// </remarks>
    private void LoadSettings()
    {
        var values = ApplicationData.Current.LocalSettings.Values;

        if (values.ContainsKey("Host") && values["Host"] is string host)
        {
            HostBox.Text = host;
        }

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

        values["Host"] = HostBox.Text;

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
    /// Reads the saved connections and loads the entry for the remembered host, if there is one.
    /// </summary>
    private void LoadConnections()
    {
        try
        {
            _connections = File.Exists(ConnectionsPath)
                ? ConnectionsFile.Parse(File.ReadAllText(ConnectionsPath))
                : ConnectionsFile.NewRoot();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException)
        {
            // Refusing to start over a broken file would leave no way to repair it from here. The
            // entries on disk are only overwritten if the user saves without restoring the file.
            Log($"Could not read {ConnectionsFile.FileName}: {ex.Message}");
            _connections = ConnectionsFile.NewRoot();
        }

        RefreshHostList();

        if (ConnectionsFile.FindEntry(_connections, HostBox.Text.Trim()) is { } entry)
        {
            LoadEntry(entry);
        }
    }

    private void RefreshHostList()
    {
        // Resetting the item source clears the box, and it does so asynchronously, so putting the
        // text back directly does not stick. Selecting the matching item does - the control then
        // owns the text - and after a save the current host is always in the list. Only a host that
        // was never saved falls back to the direct restore.
        var text = HostBox.Text;
        var hosts = ConnectionsFile.Hosts(_connections);

        _loadingEntry = true;
        HostBox.ItemsSource = hosts;
        var selected = hosts.Find(h => string.Equals(h, text.Trim(), StringComparison.OrdinalIgnoreCase));
        if (selected is not null)
        {
            HostBox.SelectedItem = selected;
        }
        else
        {
            HostBox.Text = text;
        }

        _loadingEntry = false;
    }

    private void OnHostSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loadingEntry || HostBox.SelectedItem is not string host)
        {
            return;
        }

        if (ConnectionsFile.FindEntry(_connections, host) is { } entry)
        {
            LoadEntry(entry);
        }
    }

    /// <summary>
    /// Fills the form from a saved entry. Absent elements reset to their defaults, so an entry that
    /// omits a value does not inherit whatever the previous connection left in the box.
    /// </summary>
    private void LoadEntry(XElement entry)
    {
        static string? Value(XElement entry, string name)
        {
            var text = entry.Element(name)?.Value.Trim();
            return string.IsNullOrEmpty(text) ? null : text;
        }

        static string Joined(XElement entry, string name)
            => string.Join(", ", entry.Elements(name).Select(e => e.Value.Trim()).Where(v => v.Length > 0));

        _loadingEntry = true;

        HostBox.Text = ConnectionsFile.HostOf(entry) ?? HostBox.Text;
        ProfileNameBox.Text = Value(entry, "ProfileName") ?? ProfileNameBox.Text;
        PortBox.Text = Value(entry, "Port") ?? "22";
        UserNameBox.Text = Value(entry, "UserName") ?? string.Empty;
        FingerprintBox.Text = Value(entry, "HostKeyFingerprint") ?? string.Empty;
        ClientAddressBox.Text = Value(entry, "ClientIPv4") ?? string.Empty;
        ClientIPv6Box.Text = Value(entry, "ClientIPv6") ?? string.Empty;
        ExcludeRoutesBox.Text = Joined(entry, "ExcludeRoute");
        DnsBox.Text = Joined(entry, "DnsServer");
        KeyFileBox.Text = Value(entry, "PrivateKeyFile") ?? string.Empty;
        MtuBox.Text = Value(entry, "Mtu") ?? "1400";
        OpenTimeoutBox.Text = Value(entry, "OpenTimeoutSeconds") ?? "3";
        StartDelayBox.Text = Value(entry, "StartDelaySeconds") ?? "0";
        _privateKeyToken = Value(entry, "PrivateKeyToken") ?? string.Empty;

        _loadingEntry = false;
    }

    private void WriteConnections()
    {
        // Indented on purpose - the file is in the package's local folder where a user can read and
        // hand-edit it - and written to the side first so a failure cannot half-write the store.
        var temp = ConnectionsPath + ".tmp";
        File.WriteAllText(temp, _connections.ToString());
        File.Move(temp, ConnectionsPath, overwrite: true);
    }

    /// <summary>
    /// Picks the private key and keeps durable access to it, which is what lets the package declare
    /// no file-system capability.
    /// </summary>
    /// <remarks>
    /// The FutureAccessList entry keeps the picked file readable across restarts, and the token is a
    /// string, so it travels in the saved connection like any other setting. It works from a
    /// Settings-driven connect too, because the list is package-scoped and the background-task host
    /// is part of this package. Only the plug-in reads the key; this process just picks it.
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
            Log("Save to carry it to the plug-in.");
        });
    }

    /// <summary>
    /// Saves the form as the host's configuration. Touches no VPN profile: this edits what any
    /// profile naming this server - created here or in Settings - resolves at connect.
    /// </summary>
    private async void OnSaveConnectionClick(object sender, RoutedEventArgs e)
    {
        await RunAsync("Save connection", () =>
        {
            var host = HostBox.Text.Trim();
            if (host.Length == 0)
            {
                throw new InvalidOperationException("Enter the SSH server host name.");
            }

            if (!uint.TryParse(PortBox.Text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out _))
            {
                throw new InvalidOperationException("The port must be a number.");
            }

            SaveSettings();

            var entry = BuildEntry();
            ConnectionsFile.Upsert(_connections, entry);
            WriteConnections();
            RefreshHostList();
            Log($"Saved connection '{ConnectionsFile.HostOf(entry)}' to {ConnectionsFile.FileName}");
            return Task.CompletedTask;
        });
    }

    /// <summary>
    /// Creates or updates the named VPN profile as a pointer at the current host.
    /// </summary>
    /// <remarks>
    /// Wanted only for a profile provisioned from here - one added through Settings' own "Add VPN"
    /// dialog already points at its server and needs nothing from this button.
    /// </remarks>
    private async void OnSaveProfileClick(object sender, RoutedEventArgs e)
    {
        await RunAsync("Save profile", async () =>
        {
            var profile = BuildProfile();

            if (ConnectionsFile.FindEntry(_connections, HostBox.Text.Trim()) is null)
            {
                Log($"Note: no saved connection matches '{HostBox.Text.Trim()}' yet - "
                    + "a connect will refuse until one is saved");
            }

            // Add refuses when a profile of this name already exists, so fall back to update.
            // Getting this wrong is quiet and expensive: the save reports a failure, the old
            // profile stays in place, and the next Connect exercises the previous settings.
            var status = await _agent.AddProfileFromObjectAsync(profile);
            if (status != VpnManagementErrorStatus.Ok)
            {
                Log($"AddProfileFromObjectAsync: {status}; updating the existing profile instead");
                status = await _agent.UpdateProfileFromObjectAsync(profile);
                Log($"UpdateProfileFromObjectAsync: {status}");
            }
            else
            {
                Log($"AddProfileFromObjectAsync: {status}");
            }

            Log($"Profile '{profile.ProfileName}' points at {HostBox.Text.Trim()}");
        });
    }

    /// <summary>
    /// Removes the saved connection for the current host. The VPN profile, if any, is untouched.
    /// </summary>
    private async void OnRemoveConnectionClick(object sender, RoutedEventArgs e)
    {
        await RunAsync("Remove connection", () =>
        {
            var host = HostBox.Text.Trim();
            if (host.Length == 0)
            {
                Log("Remove connection: enter or pick a host first");
                return Task.CompletedTask;
            }

            if (!ConnectionsFile.Remove(_connections, host))
            {
                Log($"No saved connection matches '{host}'");
                return Task.CompletedTask;
            }

            WriteConnections();
            RefreshHostList();
            Log($"Removed the saved connection for '{host}'");
            return Task.CompletedTask;
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
    /// It is also how the Settings dialog's storage was established: the server lands in ServerUris
    /// as http://&lt;host&gt;/, and CustomConfiguration holds the placeholder &lt;xml&gt;&lt;/xml&gt;.
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

        if (!uint.TryParse(PortBox.Text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out _))
        {
            throw new InvalidOperationException("The port must be a number.");
        }

        var profileName = ProfileNameBox.Text.Trim();
        if (profileName.Length == 0)
        {
            throw new InvalidOperationException("Enter a profile name.");
        }

        // No CustomConfiguration, deliberately: the profile is a pointer, and the settings live in
        // the connections file where the plug-in looks the server up - the same path a profile added
        // through Settings takes. A profile that does carry one (admin-pushed, or saved by an older
        // build of this app) overrides the file wholesale.
        var profile = new VpnPlugInProfile
        {
            ProfileName = profileName,
            AlwaysOn = false,
            RememberCredentials = true,

            // Points the platform at the plug-in inside this package.
            VpnPluginPackageFamilyName = Package.Current.Id.FamilyName,
        };

        // The platform hands these to the plug-in as VpnChannelConfiguration.ServerHostNameList,
        // which it builds by pulling the host out of each URI. http:// mimics what Settings' own
        // "Add VPN" dialog stores (observed via List profiles), since that shape is the one the
        // lookup has to work for either way. The scheme is otherwise meaningless; the port the
        // plug-in dials comes from the saved connection's <Port>.
        profile.ServerUris.Add(new Uri($"http://{host}"));

        return profile;
    }

    /// <summary>
    /// Builds the saved-connection entry from the form.
    /// </summary>
    /// <remarks>
    /// The entry is exactly the <c>&lt;SshVpnConfiguration&gt;</c> fragment a profile would
    /// otherwise embed, plus bookkeeping only this app reads (<c>&lt;ProfileName&gt;</c>,
    /// <c>&lt;PrivateKeyFile&gt;</c>) — the plug-in reads elements by name and ignores the rest.
    /// </remarks>
    private XElement BuildEntry()
    {
        var root = new XElement(
            ConnectionsFile.EntryElementName,
            new XElement("Host", HostBox.Text.Trim()),
            new XElement("Port", PortBox.Text.Trim()));

        // Both client addresses are written only when pinned. Empty means the plug-in chooses one at
        // connect out of what the routing table shows is free - which cannot be decided from here,
        // because the answer belongs to whichever network the machine is on at the time.
        var clientIPv4 = ClientAddressBox.Text.Trim();
        if (clientIPv4.Length > 0)
        {
            root.Add(new XElement("ClientIPv4", clientIPv4));
        }

        var clientIPv6 = ClientIPv6Box.Text.Trim();
        if (clientIPv6.Length > 0)
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

        // App-only bookkeeping, ignored by the plug-in's reader.
        var profileName = ProfileNameBox.Text.Trim();
        if (profileName.Length > 0)
        {
            root.Add(new XElement("ProfileName", profileName));
        }

        var keyFile = KeyFileBox.Text.Trim();
        if (keyFile.Length > 0)
        {
            root.Add(new XElement("PrivateKeyFile", keyFile));
        }

        return root;
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
        SaveProfileButton.IsEnabled = !busy;
        ConnectButton.IsEnabled = !busy;
        DisconnectButton.IsEnabled = !busy;
        DeleteButton.IsEnabled = !busy;
        ListButton.IsEnabled = !busy;
        RemoveButton.IsEnabled = !busy;
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
