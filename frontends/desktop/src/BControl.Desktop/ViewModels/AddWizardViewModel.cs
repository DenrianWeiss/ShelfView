using BControl.Core.Ipmi;
using BControl.Core.Native;
using BControl.Core.Localization;
using BControl.Core.Redfish;
using BControl.Desktop.Services;

namespace BControl.Desktop.ViewModels;
public sealed class WizardSystemItem : ViewModelBase
{
    public DiscoveredSystem System { get; }
    public string Display => $"{System.Name} ({System.Uri})";

    private bool _isSelected;
    public bool IsSelected { get => _isSelected; set => SetProperty(ref _isSelected, value); }

    public WizardSystemItem(DiscoveredSystem system) => System = system;
}

/// <summary>添加向导：只读探测（Redfish Session 优先，明确不支持才 Basic 由核心决定）、
/// IPMI 能力探测、多系统显式选择、套件 3 显式确认、失败可保存未验证记录。</summary>
public sealed class AddWizardViewModel : ViewModelBase
{
    public enum WizardStep
    {
        Input,
        Probing,
        Results,
        SaveFailure
    }

    private readonly Func<ServerRecord, StoredCredential, bool, StoredCredential?, Task> _save;
    public AddWizardViewModel(Func<ServerRecord, StoredCredential, bool, StoredCredential?, Task> save) => _save = save;
    private readonly CancellationTokenSource _probeCancellation = new();
    private int _protocolChoice;
    public int ProtocolChoice { get => _protocolChoice; set { if (SetProperty(ref _protocolChoice, value)) ResetProbe(); } }

    public void CancelProbe() => _probeCancellation.Cancel();
    private WizardStep _step = WizardStep.Input;
    public WizardStep Step
    {
        get => _step;
        set
        {
            if (SetProperty(ref _step, value))
            {
                RaiseChanged(nameof(IsNotProbing));
            }
        }
    }

    public bool IsNotProbing => Step != WizardStep.Probing;
    public bool HasSystems => Systems.Count > 0;
    public bool CanEditName => HasSystems || FailureMessage.Length > 0;

    private string _address = "";
    public string Address { get => _address; set { if (SetProperty(ref _address, value)) ResetProbe(); } }

    private string _username = "";
    public string Username { get => _username; set { if (SetProperty(ref _username, value)) ResetProbe(); } }

    private string _password = "";
    public string Password { get => _password; set { if (SetProperty(ref _password, value)) ResetProbe(); } }

    private bool _proxyEnabled, _proxyAuthenticate;
    private string _proxyHost = "", _proxyPort = "1080", _proxyUsername = "", _proxyPassword = "";
    public bool ProxyEnabled { get => _proxyEnabled; set { if (SetProperty(ref _proxyEnabled, value)) ResetProbe(); } }
    public bool ProxyAuthenticate { get => _proxyAuthenticate; set { if (SetProperty(ref _proxyAuthenticate, value)) ResetProbe(); } }
    public string ProxyHost { get => _proxyHost; set { if (SetProperty(ref _proxyHost, value)) ResetProbe(); } }
    public string ProxyPort { get => _proxyPort; set { if (SetProperty(ref _proxyPort, value)) ResetProbe(); } }
    public string ProxyUsername { get => _proxyUsername; set { if (SetProperty(ref _proxyUsername, value)) ResetProbe(); } }
    public string ProxyPassword { get => _proxyPassword; set { if (SetProperty(ref _proxyPassword, value)) ResetProbe(); } }

    private string _timeoutSeconds = "";
    public string TimeoutSeconds { get => _timeoutSeconds; set { if (SetProperty(ref _timeoutSeconds, value)) ResetProbe(); } }
    private Core.HostTimeout? TimeoutInput()
    {
        var text = TimeoutSeconds.Trim();
        if (text.Length == 0) return null;
        if (!uint.TryParse(text, out var seconds) || seconds is < 1 or > 3600)
            throw new InvalidOperationException(Loc.T("connection.invalidTimeout"));
        return new Core.HostTimeout(seconds);
    }

    private int _probeRevision;
    private void ResetProbe()
    {
        ++_probeRevision;
        TlsDetails = "";
        _redfishOk = _ipmiOk = false; _graphicalConsole = null;
        Systems.Clear();
        if (IsNotProbing) Step = WizardStep.Input;
        RaiseChanged(nameof(HasSystems)); RaiseChanged(nameof(MultipleSystems)); RaiseChanged(nameof(CanEditName));
    }

    private (ServerProxy? Configuration, StoredCredential? Credential, Core.Socks5Connection? Connection) ProxyInput()
    {
        if (!ProxyEnabled) return (null, null, null);
        if (!ushort.TryParse(ProxyPort, out var port) || port == 0)
            throw new BcException(Bc.InvalidArgument, Bc.StatusText(Bc.InvalidArgument));
        var credential = ProxyAuthenticate ? new StoredCredential(ProxyUsername, ProxyPassword) : null;
        if (credential != null && credential.Username.Length == 0)
            throw new InvalidOperationException(Loc.T("proxy.credentialUnavailable"));
        var connection = new Core.Socks5Connection(ProxyHost.Trim(), port, credential?.Username ?? "", credential?.Password ?? "");
        var configuration = new ServerProxy { Host = connection.Host, Port = port, Username = credential?.Username ?? "",
            CredentialRef = credential == null ? null : Guid.NewGuid().ToString("N") };
        return (configuration, credential, connection);
    }

    private string? _caFile;
    public string? CaFile { get => _caFile; set { if (SetProperty(ref _caFile, value)) ResetProbe(); } }

    private int _minimumTlsIndex = 2;
    public int MinimumTlsIndex
    {
        get => _minimumTlsIndex;
        set
        {
            if (SetProperty(ref _minimumTlsIndex, value))
            {
                SecurityConfirmed = false;
                ResetProbe();
            }
        }
    }

    public uint MinimumTls => (uint)(Math.Clamp(MinimumTlsIndex, 0, 3) + 10);

    private bool _securityConfirmed;
    public bool SecurityConfirmed { get => _securityConfirmed; set => SetProperty(ref _securityConfirmed, value); }

    private uint _certPolicy = Bc.CertStrict;
    public uint CertPolicy
    {
        get => _certPolicy;
        set
        {
            if (SetProperty(ref _certPolicy, value))
            {
                SecurityConfirmed = false;
                ResetProbe();
            }
        }
    }

    private string _tlsDetails = "";
    public string TlsDetails { get => _tlsDetails; private set => SetProperty(ref _tlsDetails, value); }

    private string _progress = "";
    public string Progress { get => _progress; set => SetProperty(ref _progress, value); }

    private bool _requiresSuite3Confirmation;
    public bool RequiresSuite3Confirmation { get => _requiresSuite3Confirmation; set => SetProperty(ref _requiresSuite3Confirmation, value); }

    private bool _suite3Confirmed;
    public bool Suite3Confirmed { get => _suite3Confirmed; set => SetProperty(ref _suite3Confirmed, value); }
    public List<WizardSystemItem> Systems { get; } = new();
    public bool MultipleSystems => Systems.Count > 1;
    private DiscoveredSystem? SelectedSystem => Systems.FirstOrDefault(s => s.IsSelected)?.System ?? (Systems.Count == 1 ? Systems[0].System : null);

    private bool _redfishOk;
    private bool _ipmiOk;
    private string _failureMessage = "";
    public string FailureMessage
    {
        get => _failureMessage;
        set
        {
            if (SetProperty(ref _failureMessage, value))
                RaiseChanged(nameof(CanEditName));
        }
    }

    public string? FailureKey { get; private set; }

    private void Fail(string key)
    {
        FailureKey = key;
        FailureMessage = Loc.T(key);
    }

    private void ClearFailure()
    {
        FailureKey = null;
        FailureMessage = "";
    }

    private string _displayName = "";
    public string DisplayName { get => _displayName; set => SetProperty(ref _displayName, value); }
    public bool CanSaveUnverified => !string.IsNullOrWhiteSpace(Address);

    public async Task ProbeAsync()
    {
        if (!IsNotProbing || _probeCancellation.IsCancellationRequested) return;
        if ((CertPolicy != Bc.CertStrict || MinimumTls < 12) && !SecurityConfirmed)
        {
            FailureMessage = Loc.T("add.securityConfirmation");
            return;
        }

        if (string.IsNullOrWhiteSpace(Address) || string.IsNullOrWhiteSpace(Username))
        {
            Fail("add.required");
            return;
        }

        Core.Socks5Connection? proxy;
        try { _ = TimeoutInput(); proxy = ProxyInput().Connection; }
        catch (Exception ex) { FailureMessage = ex.Message; return; }
        ResetProbe();
        var revision = _probeRevision;
        Step = WizardStep.Probing;
        RequiresSuite3Confirmation = false;
        ClearFailure();
        try
        {
            var credential = new DeviceCredential(Username, Password ?? "");
            var progress = new Progress<string>(message => { if (revision == _probeRevision && !IsNotProbing) Progress = message; });
            var redfishTask = ProtocolChoice == 2 ? Task.FromResult<Exception?>(null) : ProbeRedfishAsync(credential, progress, proxy);
            var ipmiTask = ProtocolChoice == 1 ? Task.FromResult<(Exception? Exception, IpmiCapabilities? Caps, bool? SolEnabled)>((null, null, null)) : ProbeIpmiAsync(credential, proxy);
            await Task.WhenAll(redfishTask, ipmiTask);
            if (_probeCancellation.IsCancellationRequested) return;
            var redfishError = await redfishTask;
            var ipmi = await ipmiTask;
            if (redfishError != null)
            {
                FailureKey = "error.probeFailed";
                FailureMessage = redfishError.Message;
                if (redfishError is DiscoveryFailure { Status: Bc.TlsError })
                    _ = LoadTlsDetailsAsync(Address, proxy, revision);
            }
            RequiresSuite3Confirmation = ipmi.Exception is Suite3ConfirmationRequiredException;
            if (Systems.Count > 0 && string.IsNullOrEmpty(DisplayName)) DisplayName = Systems[0].System.Name;
            Progress = MultipleSystems ? Loc.T("add.multipleSystems") : "";
        }
        catch (OperationCanceledException) when (_probeCancellation.IsCancellationRequested) { }
        catch (Exception ex) { FailureKey = "error.probeFailed"; FailureMessage = ex.Message; }
        finally
        {
            Step = WizardStep.Results;
            RaiseChanged(nameof(HasSystems));
            RaiseChanged(nameof(MultipleSystems));
            RaiseChanged(nameof(CanEditName));
        }
    }

    private async Task<Exception?> ProbeRedfishAsync(DeviceCredential credential, IProgress<string> progress, Core.Socks5Connection? proxy)
    {
        try
        {
            var result = await DiscoveryService.ProbeAsync(Address.Trim(), credential, CaFile ?? "", CertPolicy, cancellation: _probeCancellation.Token, budgetMilliseconds: 15000, progress: progress, tlsMin: MinimumTls, proxy: proxy, timeout: TimeoutInput());
            foreach (var system in result.Systems)
                Systems.Add(new WizardSystemItem(system));
            _redfishOk = result.Systems.Count > 0;
            return null;
        }
        catch (Exception ex) { return ex; }
    }

    private async Task LoadTlsDetailsAsync(string address, Core.Socks5Connection? proxy, int revision)
    {
        try
        {
            var peer = await Core.Security.TlsDiagnostics.ProbeAsync(address, _probeCancellation.Token, proxy);
            if (peer != null && revision == _probeRevision && !_probeCancellation.IsCancellationRequested)
                TlsDetails = Loc.T("add.securityMismatchBody") + "\n" + string.Join("\n", new[] { Loc.T("add.detectedTLS") + ": " + peer.Version, Loc.T("add.detectedCipher") + ": " + peer.Cipher, Loc.T("add.certificateSubject") + ": " + peer.Subject, Loc.T("add.certificateIssuer") + ": " + peer.Issuer, Loc.T("add.certificateFingerprint") + ": " + peer.Sha256, Loc.T("add.certificateValidity") + ": " + peer.NotBefore.ToString("u") + " – " + peer.NotAfter.ToString("u") });
        }
        catch (Exception) { /* Optional diagnostics must not affect the probe result. */ }
    }

    private bool? _graphicalConsole;

    private async Task<(Exception? Exception, Core.Ipmi.IpmiCapabilities? Caps, bool? SolEnabled)> ProbeIpmiAsync(DeviceCredential credential, Core.Socks5Connection? proxy)
    {
        try
        {
            var(host, port) = SolWorkspaceViewModel.ParseAddress(Address, 2);
            var timeout = TimeoutInput();
            using var operation = new Core.OperationBudget(timeout?.Milliseconds ?? 15000);
            await using var connection = await IpmiConnection.OpenAsync(host, port, credential.Username, credential.Password, _suite3Confirmed, _probeCancellation.Token, proxy, timeout, operation);
            var caps = await connection.ProbeAsync();
            _graphicalConsole = caps.GraphicalConsole;
            var config = await connection.GetSolConfigAsync();
            _ipmiOk = true;
            return (null, caps, config?.ConfigurationKnown == true ? config.Enabled : null);
        }
        catch (Exception ex)
        {
            return (ex, null, null);
        }
    }

    /// <summary>套件 3 显式确认后重试 IPMI 探测。</summary>
    public async Task ConfirmSuite3AndProbeIpmiAsync()
    {
        if (!Suite3Confirmed)
            return;
        RequiresSuite3Confirmation = false;
        var credential = new DeviceCredential(Username, Password ?? "");
        Core.Socks5Connection? proxy;
        try { _ = TimeoutInput(); proxy = ProxyInput().Connection; }
        catch (Exception ex) { FailureMessage = ex.Message; return; }
        var(exception, _, _) = await ProbeIpmiAsync(credential, proxy);
        if (exception == null)
        {
            ClearFailure();
        }
    }

    public async Task<ServerRecord?> SaveAsync(bool saveUnverified)
    {
        if ((CertPolicy != Bc.CertStrict || MinimumTls < 12) && !SecurityConfirmed)
        {
            FailureMessage = Loc.T("add.securityConfirmation");
            return null;
        }

        if (Step == WizardStep.Probing)
            return null;
        if (Systems.Count == 0 && !_ipmiOk && !saveUnverified)
        {
            Fail("add.probeFailedSaveUnverified");
            return null;
        }

        var selected = SelectedSystem;
        if (Systems.Count > 1 && selected == null)
        {
            Fail("add.mustSelectSystem");
            return null;
        }

        var proxy = ProxyInput();
        var serverId = Guid.NewGuid().ToString("N");
        var record = new ServerRecord
        {
            ServerId = serverId,
            Proxy = proxy.Configuration,
            Timeout = TimeoutInput(),
            EndpointId = Guid.NewGuid().ToString("N"),
            Name = string.IsNullOrWhiteSpace(DisplayName) ? (selected?.Name ?? Address.Trim()) : DisplayName.Trim(),
            Address = Address.Trim(),
            Protocol = _redfishOk ? 1u : (_ipmiOk ? 2u : (uint)ProtocolChoice),
            SystemUri = selected?.Uri ?? "",
            Username = Username,
            Verified = _redfishOk || _ipmiOk,
            VerificationErrorKey = (_redfishOk || _ipmiOk) ? null : (FailureKey ?? "add.probeFailed"),
            VerificationError = (_redfishOk || _ipmiOk) ? null : (FailureMessage.Length > 0 ? FailureMessage : Loc.T("add.probeFailed")),
            CaFile = string.IsNullOrEmpty(CaFile) ? null : CaFile,
            CertPolicy = CertPolicy,
            MinimumTls = MinimumTls,
            Suite3Confirmed = Suite3Confirmed,
            Capabilities = new ServerCapabilities
            {
                Redfish = _redfishOk,
                Ipmi = _ipmiOk,
                Kvm = _redfishOk || _ipmiOk,
                GraphicalConsole = _graphicalConsole,
                Sol = _ipmiOk,
                MediaRedfish = _redfishOk,
            },
        };
        var credential = new StoredCredential(Username, Password ?? "");
        await _save(record, credential, record.Verified, proxy.Credential);
        return record;
    }
}
