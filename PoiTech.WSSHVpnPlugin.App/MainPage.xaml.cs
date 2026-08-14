using System;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Windows.ApplicationModel;
using Windows.Networking.Vpn;
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
    private const string ProfileName = "SSH VPN";

    private readonly VpnManagementAgent _agent = new();

    public MainPage()
    {
        InitializeComponent();
    }

    private async void OnSaveProfileClick(object sender, RoutedEventArgs e)
    {
        await RunAsync("Save profile", async () =>
        {
            var profile = BuildProfile();
            var status = await _agent.AddProfileFromObjectAsync(profile);
            Log($"AddProfileFromObjectAsync: {status}");
        });
    }

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
        var host = HostBox.Text.Trim();
        if (host.Length == 0)
        {
            throw new InvalidOperationException("Enter the SSH server host name.");
        }

        if (!uint.TryParse(PortBox.Text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var port))
        {
            throw new InvalidOperationException("The port must be a number.");
        }

        var profile = new VpnPlugInProfile
        {
            ProfileName = ProfileName,
            AlwaysOn = false,
            RememberCredentials = true,

            // Points the platform at the plug-in inside this package.
            VpnPluginPackageFamilyName = Package.Current.Id.FamilyName,

            CustomConfiguration = BuildCustomConfiguration(port),
        };

        // The platform hands these to the plug-in as VpnChannelConfiguration.ServerHostNameList.
        profile.ServerUris.Add(new Uri($"ssh://{host}:{port}"));

        return profile;
    }

    private string BuildCustomConfiguration(uint port)
    {
        var root = new XElement(
            "SshVpnConfiguration",
            new XElement("Port", port.ToString(CultureInfo.InvariantCulture)),
            new XElement("ClientIPv4", ClientAddressBox.Text.Trim()));

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
