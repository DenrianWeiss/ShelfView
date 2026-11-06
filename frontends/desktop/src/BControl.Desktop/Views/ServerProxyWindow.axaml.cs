using Avalonia.Controls;
using Avalonia.Interactivity;
using BControl.Core.Localization;
using BControl.Core.Native;
using BControl.Desktop.Services;
using BControl.Desktop.ViewModels;

namespace BControl.Desktop.Views;
public partial class ServerProxyWindow : Window
{
    private readonly MainViewModel? _main;
    private readonly ServerRecord? _record;
    private StoredCredential? _proxyCredential;
    private bool _saving;
    public ServerProxyWindow()
    {
        InitializeComponent();
        Closing += (_, e) => e.Cancel = _saving;
        Closed += (_, _) => { Password.Text = ""; _proxyCredential = null; };
    }
    public ServerProxyWindow(MainViewModel main, ServerRecord record, StoredCredential? credential) : this()
    {
        _main = main; _record = record;
        _proxyCredential = credential;
        DisplayName.Text = record.Name;
        DisplayName.PlaceholderText = record.Address;
        TimeoutSeconds.Text = record.Timeout?.Seconds.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "";
        CaFile.Text = record.CaFile ?? "";
        CertificatePolicy.SelectedIndex = (int)record.CertPolicy;
        MinimumTls.SelectedIndex = (int)Math.Clamp(record.MinimumTls, 10u, 13u) - 10;
        CertificatePolicy.SelectionChanged += (_, _) => SecurityConfirmed.IsChecked = false;
        MinimumTls.SelectionChanged += (_, _) => SecurityConfirmed.IsChecked = false;
        Enabled.IsChecked = record.Proxy != null;
        if (record.Proxy is { } proxy)
        {
            Host.Text = proxy.Host; Port.Text = proxy.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
            Authenticate.IsChecked = proxy.CredentialRef != null;
            Username.Text = proxy.Username; Password.Text = credential?.Password ?? "";
        }
    }
    private void OnCancel(object? sender, RoutedEventArgs e) => Close();
    private async void OnSave(object? sender, RoutedEventArgs e)
    {
        if (_saving || _main == null || _record == null) return;
        _saving = true; Form.IsEnabled = false; Error.Text = "";
        var saved = false;
        try
        {
            BControl.Core.HostTimeout? timeout = null;
            var text = TimeoutSeconds.Text?.Trim() ?? "";
            if (text.Length != 0)
            {
                if (!uint.TryParse(text, out var seconds) || seconds is < 1 or > 3600)
                    throw new InvalidOperationException(BControl.Core.Localization.Loc.T("connection.invalidTimeout"));
                timeout = new BControl.Core.HostTimeout(seconds);
            }
            ushort port = 1080;
            if (Enabled.IsChecked == true && (!ushort.TryParse(Port.Text, out port) || port == 0))
                throw new BcException(Bc.InvalidArgument, Bc.StatusText(Bc.InvalidArgument));
            var credential = Enabled.IsChecked == true && Authenticate.IsChecked == true
                ? new StoredCredential(Username.Text ?? "", Password.Text ?? "") : null;
            var certPolicy = (uint)Math.Clamp(CertificatePolicy.SelectedIndex, 0, 2);
            var minimumTls = (uint)(Math.Clamp(MinimumTls.SelectedIndex, 0, 3) + 10);
            if ((certPolicy != Bc.CertStrict || minimumTls < 12) &&
                (certPolicy != _record.CertPolicy || minimumTls != _record.MinimumTls) && SecurityConfirmed.IsChecked != true)
                throw new InvalidOperationException(Loc.T("add.securityConfirmation"));
            var caFile = CaFile.Text?.Trim();
            var host = Enabled.IsChecked == true ? Host.Text?.Trim() ?? "" : null;
            var proxy = _record.Proxy;
            var keepProxy = proxy != null && host == proxy.Host && port == proxy.Port &&
                (Authenticate.IsChecked == true) == (proxy.CredentialRef != null) &&
                (credential == _proxyCredential ||
                 (_proxyCredential == null && credential is { Password: "" } && credential.Username == proxy.Username));
            var name = DisplayName.Text?.Trim();
            await _main.SaveConnectionAsync(_record, host, port, credential, timeout,
                string.IsNullOrEmpty(caFile) ? null : caFile, certPolicy, minimumTls,
                string.IsNullOrEmpty(name) ? _record.Address : name, keepProxy);
            saved = true;
        }
        catch (Exception ex) { Error.Text = ex.Message; }
        finally { _saving = false; Form.IsEnabled = true; }
        if (saved) Close();
    }
}
