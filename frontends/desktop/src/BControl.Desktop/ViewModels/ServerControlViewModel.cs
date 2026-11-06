using System.Collections.ObjectModel;
using BControl.Core;
using BControl.Core.Kvm;
using BControl.Core.Localization;
using BControl.Core.Native;
using BControl.Core.Redfish;
using BControl.Desktop.Services;

namespace BControl.Desktop.ViewModels;
/// <summary>
/// 单台服务器的电源与一次性启动设置。电源动作来自设备公布的 Reset ActionInfo；
/// 启动设置只提交一次性覆盖并在可用时读回，不修改持久启动顺序。
/// </summary>
public sealed class ServerControlViewModel : ViewModelBase, IDisposable
{
    private static readonly string[] PowerKeys =
    {
        "power.action.on",
        "power.action.forceOff",
        "power.action.gracefulShutdown",
        "power.action.gracefulRestart",
        "power.action.forceRestart",
        "power.action.nmi",
        "power.action.forceOn",
        "power.action.pushPowerButton",
        "power.action.powerCycle",
    };
    private static readonly string[] TargetKeys =
    {
        "boot.target.none",
        "boot.target.pxe",
        "boot.target.disk",
        "boot.target.cd",
        "boot.target.setup",
        "boot.target.usb",
        "boot.target.uefiShell",
        "boot.target.remoteCD",
        "boot.target.remoteFloppy",
        "boot.target.remoteDisk",
        "boot.target.remotePrimary",
        "boot.target.floppy",
    };
    private readonly ServerRecord _record;
    private readonly Func<Task<StoredCredential?>> _getCredential;
    private readonly IServerControlService _service;
    private readonly CancellationTokenSource _load = new();
    private DiscoveryService.ControlSnapshot? _snapshot;
    private bool _disposed;
    public ServerControlViewModel(ServerRecord record, Func<Task<StoredCredential?>> getCredential, IServerControlService? service = null)
    {
        _record = record;
        _getCredential = getCredential;
        Sensors = new(record, getCredential, "sensors");
        Sel = new(record, getCredential, "sel");
        Inventory = new(record, getCredential, "inventory");
        Network = new(record, getCredential, "network");
        _service = service ?? (record.Protocol == 2 ? new IpmiServerControlService() : new RedfishServerControlService());
    }

    public ManagementDataViewModel Sensors { get; }
    public ManagementDataViewModel Sel { get; }
    public ManagementDataViewModel Inventory { get; }
    public ManagementDataViewModel Network { get; }
    private ConsoleModeSettings? _consoleMode;
    private bool _consoleModeLoaded, _consoleModeBusy;
    private string _consoleModeStatus = "";
    public bool FocusConsoleMode { get; init; }
    public bool ShowConsoleMode => _consoleMode != null || FocusConsoleMode || !string.IsNullOrEmpty(_consoleModeStatus);
    public bool CanSwitchConsoleMode => !_consoleModeBusy && _consoleMode?.Alternative != null;
    public bool ConsoleModeBusy => _consoleModeBusy;
    public string ConsoleModeStatus => _consoleModeStatus;
    public string ConsoleModeCurrent => _consoleMode is { } settings
        ? Loc.F("manage.consoleMode.current", ("mode", ConsoleModeSettings.Title(settings.Current))) : "";
    public string ConsoleModeSwitchLabel => _consoleMode?.Alternative is { } target
        ? Loc.F("manage.consoleMode.switch", ("mode", ConsoleModeSettings.Title(target))) : "";

    public async Task LoadConsoleModeAsync(bool refresh = false)
    {
        if (_consoleModeBusy || (_consoleModeLoaded && !refresh)) return;
        await UpdateConsoleModeAsync();
    }

    public async Task SwitchConsoleModeAsync(Func<string, Task<bool>> confirm)
    {
        if (!CanSwitchConsoleMode || _consoleMode is not { } settings || settings.Alternative is not { } target) return;
        if (await confirm(Loc.F("manage.consoleMode.confirm", ("mode", ConsoleModeSettings.Title(target)))) &&
            !_consoleModeBusy && !_disposed && _consoleMode == settings)
            await UpdateConsoleModeAsync(settings.Current, target);
    }

    private async Task UpdateConsoleModeAsync(ConsoleMode? expected = null, ConsoleMode? target = null)
    {
        _consoleModeBusy = true;
        _consoleModeStatus = "";
        NotifyConsoleMode();
        try
        {
            var credential = await _getCredential() ?? throw new InvalidOperationException(Loc.T("error.credentialsUnavailable"));
            _consoleMode = await ConsoleConnectionFactory.GetOrSetModeAsync(_record, credential, _load.Token, expected, target);
            _consoleModeLoaded = true;
            if (target is { } mode)
                _consoleModeStatus = Loc.F("manage.consoleMode.changed", ("mode", ConsoleModeSettings.Title(mode)));
            else if (_consoleMode == null && FocusConsoleMode)
                _consoleModeStatus = Loc.T("manage.consoleMode.unavailable");
        }
        catch (OperationCanceledException) when (_disposed) { }
        catch (Exception error)
        {
            var report = target != null || FocusConsoleMode || _consoleMode != null;
            _consoleMode = null;
            _consoleModeLoaded = false;
            if (report)
                _consoleModeStatus = error switch
                {
                    BcException { Status: Bc.OutcomeUnknown } => Loc.T("manage.consoleMode.unconfirmed"),
                    BcException { Status: Bc.Busy } when target != null => Loc.T("manage.consoleMode.unchanged"),
                    BcException { Status: Bc.HttpError } when target != null =>
                        error.Message + " " + Loc.T("manage.consoleMode.retry"),
                    _ => error.Message
                };
        }
        finally
        {
            _consoleModeBusy = false;
            NotifyConsoleMode();
        }
    }

    private void NotifyConsoleMode()
    {
        RaiseChanged(nameof(ShowConsoleMode));
        RaiseChanged(nameof(CanSwitchConsoleMode));
        RaiseChanged(nameof(ConsoleModeBusy));
        RaiseChanged(nameof(ConsoleModeStatus));
        RaiseChanged(nameof(ConsoleModeCurrent));
        RaiseChanged(nameof(ConsoleModeSwitchLabel));
    }
    public bool IsIpmi => _record.Protocol == 2;
    public string ServerName => _record.Name;
    public string Title => Loc.F("server.controlTitle", ("name", _record.Name));
    public string PowerHeading => Loc.T("power.actions");
    public string BootHeading => Loc.T("boot.title");
    public string TargetLabel => Loc.T("boot.target");
    public string ModeLabel => Loc.T("boot.mode");
    public ObservableCollection<PowerOption> PowerActions { get; } = new();
    public ObservableCollection<BootTargetOption> BootTargets { get; } = new();
    public ObservableCollection<BootModeOption> BootModes { get; } = new();

    public sealed record PowerOption(uint Action, string Label);
    public sealed record BootTargetOption(uint Target, string Label);
    public sealed record BootModeOption(uint Mode, string Label);
    private PowerOption? _selectedPower;
    public PowerOption? SelectedPower
    {
        get => _selectedPower;
        set
        {
            if (SetProperty(ref _selectedPower, value))
                RaiseChanged(nameof(CanApplyPower));
        }
    }

    private BootTargetOption? _selectedTarget;
    public BootTargetOption? SelectedTarget
    {
        get => _selectedTarget;
        set
        {
            if (SetProperty(ref _selectedTarget, value))
                RaiseChanged(nameof(CanApplyBoot));
        }
    }

    private BootModeOption? _selectedMode;
    public BootModeOption? SelectedMode
    {
        get => _selectedMode;
        set
        {
            if (SetProperty(ref _selectedMode, value))
                RaiseChanged(nameof(CanApplyBoot));
        }
    }

    private bool _busy;
    public bool IsBusy
    {
        get => _busy;
        private set
        {
            if (!SetProperty(ref _busy, value))
                return;
            RaiseChanged(nameof(CanApplyPower));
            RaiseChanged(nameof(CanApplyBoot));
        }
    }

    private string _status = "";
    public string Status { get => _status; private set => SetProperty(ref _status, value); }

    private string _powerStatus = Loc.T("power.settingsNotRead");
    public string PowerStatus { get => _powerStatus; private set => SetProperty(ref _powerStatus, value); }

    private string _bootStatus = Loc.T("boot.settingsNotRead");
    public string BootStatus { get => _bootStatus; private set => SetProperty(ref _bootStatus, value); }

    private bool _bootSupported;
    private bool _bootOnceAdvertised;
    private bool _bootTargetsKnown;
    public bool CanApplyPower => !IsBusy && SelectedPower != null;
    public bool CanApplyBoot => !IsBusy && _bootSupported && _bootOnceAdvertised && ((_snapshot?.Boot?.Flags ?? 0) & BootAbi.Locked) == 0 && (_record.Protocol != 2 || SelectedTarget?.Target == BootAbi.None || SelectedMode?.Mode != BootAbi.ModePreserve || ((_snapshot?.Boot?.Flags ?? 0) & BootAbi.Enabled) != 0) && (_bootTargetsKnown || ((_snapshot?.Boot?.Flags ?? 0) & BootAbi.Enabled) != 0) && SelectedTarget != null && SelectedMode != null;
    public bool Changed { get; private set; }

    public async Task LoadAsync()
    {
        if (IsBusy)
            return;
        IsBusy = true;
        Status = Loc.T("server.controlLoading");
        PowerStatus = Loc.T("power.settingsNotRead");
        BootStatus = Loc.T("boot.settingsNotRead");
        try
        {
            if (_record.Protocol != 2 && string.IsNullOrEmpty(_record.SystemUri))
            {
                Status = Loc.T("server.systemSelectionRequired");
                return;
            }

            var stored = await _getCredential();
            if (stored == null)
            {
                Status = Loc.T("error.credentialsUnavailable");
                return;
            }

            _snapshot = await _service.ReadAsync(_record, new DeviceCredential(stored.Username, stored.Password), _load.Token);
            Status = "";
            RenderPower();
            RenderBoot();
        }
        catch (OperationCanceledException)when (_disposed)
        {
        }
        catch (Exception ex)
        {
            Status = Describe("server.controlFailed", ex);
            PowerStatus = Loc.T("power.notProvided");
            BootStatus = Loc.T("boot.notProvided");
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task ApplyPowerAsync(Func<string, Task<bool>> confirm)
    {
        if (!CanApplyPower || SelectedPower == null)
            return;
        var action = SelectedPower;
        if (!await confirm(Loc.F("power.confirm", ("action", action.Label))))
            return;
        IsBusy = true;
        Status = "";
        try
        {
            var stored = await _getCredential();
            if (stored == null)
            {
                Status = Loc.T("error.credentialsUnavailable");
                return;
            }

            var flags = await _service.PowerAsync(_record, new DeviceCredential(stored.Username, stored.Password), action.Action, CancellationToken.None);
            PowerStatus = (flags & RedfishAbi.TaskPending) != 0 ? Loc.T("power.acceptedTask") : Loc.T("power.accepted");
            Changed = true;
        }
        catch (Exception ex)
        {
            PowerStatus = Describe("power.actionFailed", ex);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task ApplyBootAsync(Func<string, Task<bool>> confirm)
    {
        if (!CanApplyBoot || SelectedTarget == null || SelectedMode == null)
            return;
        var target = SelectedTarget;
        var mode = SelectedMode;
        if (!await confirm(Loc.F("boot.confirm", ("target", target.Label))))
            return;
        IsBusy = true;
        Status = "";
        try
        {
            var stored = await _getCredential();
            if (stored == null)
            {
                Status = Loc.T("error.credentialsUnavailable");
                return;
            }

            var result = await _service.SetBootOnceAsync(_record, new DeviceCredential(stored.Username, stored.Password), target.Target, mode.Mode, CancellationToken.None);
            if (result == null)
            {
                BootStatus = Loc.T("boot.notProvided");
                return;
            }

            if (result.Value.State is { } state)
                _snapshot = _snapshot!with
                {
                    Boot = state
                };
            BootStatus = (result.Value.Flags & RedfishAbi.BootVerified) != 0 ? Loc.T("boot.appliedReadBack") : (result.Value.Flags & RedfishAbi.TaskPending) != 0 ? Loc.T("boot.appliedTask") : Loc.T("power.accepted");
            Changed = true;
        }
        catch (Exception ex)
        {
            BootStatus = Describe("boot.writeFailed", ex);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void RenderPower()
    {
        var selected = SelectedPower?.Action;
        PowerActions.Clear();
        var mask = _snapshot?.Power?.SupportedResetTypes ?? 0;
        for (uint action = 0; action < PowerKeys.Length; action++)
            if ((mask & (1u << (int)action)) != 0)
                PowerActions.Add(new PowerOption(action, Loc.T(PowerKeys[action])));
        SelectedPower = PowerActions.FirstOrDefault(option => option.Action == selected) ?? PowerActions.FirstOrDefault();
        PowerStatus = _snapshot?.PowerReadError ?? (PowerActions.Count == 0 ? (_snapshot?.Power == null ? Loc.T("power.notProvided") : Loc.T("power.noActions")) : Loc.F("power.available", ("count", PowerActions.Count)));
    }

    private void RenderBoot()
    {
        var boot = _snapshot?.Boot;
        _bootSupported = boot != null && boot.Value.Status == Bc.Ok;
        _bootOnceAdvertised = _bootSupported && (boot!.Value.Flags & (BootAbi.OnceSupported | BootAbi.OnceInferred)) != 0;
        _bootTargetsKnown = _bootSupported && (boot!.Value.Flags & BootAbi.TargetsKnown) != 0;
        var selectedTarget = SelectedTarget?.Target;
        var selectedMode = SelectedMode?.Mode;
        BootTargets.Clear();
        BootModes.Clear();
        if (!_bootSupported)
        {
            BootStatus = _snapshot?.BootReadError ?? Loc.T("boot.notProvided");
            SelectedTarget = null;
            SelectedMode = null;
            return;
        }

        var value = boot!.Value;
        if (_bootTargetsKnown && _bootOnceAdvertised)
        {
            for (uint target = 0; target < TargetKeys.Length; target++)
                if (target == BootAbi.None || (value.SupportedTargets & (1u << (int)target)) != 0)
                    BootTargets.Add(new BootTargetOption(target, Loc.T(TargetKeys[target])));
        }
        else
        {
            BootTargets.Add(new BootTargetOption(BootAbi.None, Loc.T(TargetKeys[BootAbi.None])));
        }

        var wantedTarget = selectedTarget ?? ((value.Flags & BootAbi.Enabled) != 0 ? value.Target : BootAbi.None);
        SelectedTarget = BootTargets.FirstOrDefault(option => option.Target == wantedTarget) ?? BootTargets[0];
        BootModes.Add(new BootModeOption(BootAbi.ModePreserve, Loc.T("boot.preserve")));
        if ((value.SupportedModes & 2) != 0)
            BootModes.Add(new BootModeOption(BootAbi.ModeLegacy, Loc.T("boot.legacy")));
        if ((value.SupportedModes & 4) != 0)
            BootModes.Add(new BootModeOption(BootAbi.ModeUefi, Loc.T("boot.uefi")));
        var wantedMode = selectedMode ?? ((value.Flags & BootAbi.Enabled) != 0 ? value.Mode : BootAbi.ModePreserve);
        SelectedMode = BootModes.FirstOrDefault(option => option.Mode == wantedMode) ?? BootModes[0];
        if (!_bootOnceAdvertised)
            BootStatus = Loc.T("boot.onceUnsupported");
        else if (!_bootTargetsKnown)
            BootStatus = Loc.T("boot.targetsUnknown");
        else if ((value.Flags & BootAbi.Enabled) != 0)
            BootStatus = Loc.F("boot.override", ("mode", Loc.T((value.Flags & BootAbi.Persistent) != 0 ? "boot.continuous" : "boot.nextBoot")), ("target", TargetText(value.Target)));
        else
            BootStatus = Loc.T("boot.currentOrder");
        RaiseChanged(nameof(CanApplyBoot));
    }

    public void SetFailure(Exception error) => Status = Describe("server.controlFailed", error);
    private static string TargetText(uint target) => target < (uint)TargetKeys.Length ? Loc.T(TargetKeys[(int)target]) : Loc.T("boot.unknownDevice");
    private static string Describe(string whatKey, Exception error) => error switch
    {
        BcException bc => Loc.F("error.context", ("what", Loc.T(whatKey)), ("detail", Loc.Instance.Status(bc.Status))),
        DiscoveryFailure failure => Loc.F("error.context", ("what", Loc.T(whatKey)), ("detail", Loc.Instance.Status(failure.Status))),
        _ => Loc.F("error.context", ("what", Loc.T(whatKey)), ("detail", error.Message)),
    };
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        Sensors.Dispose();
        Sel.Dispose();
        Inventory.Dispose();
        Network.Dispose();
        _load.Cancel();
        _load.Dispose();
    }
}
