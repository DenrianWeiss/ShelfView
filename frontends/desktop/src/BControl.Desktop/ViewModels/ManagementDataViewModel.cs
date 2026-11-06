using System.Globalization;
using BControl.Core.Ipmi;
using BControl.Core.Localization;
using BControl.Core.Native;
using BControl.Core.Redfish;
using BControl.Desktop.Services;

namespace BControl.Desktop.ViewModels;
public sealed class ManagementDataViewModel : ViewModelBase, IDisposable
{
    private readonly ServerRecord _record;
    private readonly Func<Task<StoredCredential?>> _credential;
    private readonly string _section;
    private readonly CancellationTokenSource _cancellation = new();
    public IReadOnlyList<ManagementSwitch> Switches { get; private set; } = Array.Empty<ManagementSwitch>();

    public async Task ApplySwitchAsync(ManagementSwitch item, Func<string, Task<bool>> confirm)
    {
        if (IsBusy || !await confirm(item.Name + " " + Loc.T(item.Enabled ? "manage.redfish.disabled" : "manage.redfish.enabled")))
            return;
        IsBusy = true;
        try
        {
            var credential = await _credential();
            if (credential == null)
            {
                Status = Loc.T("error.credentialsUnavailable");
                return;
            }

            var proxy = await _record.ResolveProxyAsync(_cancellation.Token);
            Status = await ManagementSwitches.ApplyAsync(_record.Address, new(credential.Username, credential.Password), _record.CaFile ?? "", _record.CertPolicy, item, !item.Enabled, _cancellation.Token, _record.MinimumTls, proxy);
            _loaded = false;
        }
        catch (Exception ex)
        {
            Status = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }

        var outcome = Status;
        await LoadAsync();
        Status = outcome;
    }

    private bool _loaded;
    private bool _disposed;
    private bool _busy;
    public bool IsBusy { get => _busy; private set => SetProperty(ref _busy, value); }

    private string _status = Loc.T("sensor.notRead");
    public string Status { get => _status; private set => SetProperty(ref _status, value); }

    private IReadOnlyList<ManagementItem> _items = Array.Empty<ManagementItem>();
    public IReadOnlyList<ManagementItem> Items { get => _items; private set => SetProperty(ref _items, value); }

    public ManagementDataViewModel(ServerRecord record, Func<Task<StoredCredential?>> credential, string section)
    {
        _record = record;
        _credential = credential;
        _section = section;
    }

    public async Task LoadAsync(bool refresh = false)
    {
        if (_disposed || IsBusy || (_loaded && !refresh))
            return;
        IsBusy = true;
        Status = Loc.T("server.controlLoading");
        try
        {
            var credential = await _credential();
            if (credential == null)
            {
                Status = Loc.T("error.credentialsUnavailable");
                return;
            }

            var proxy = await _record.ResolveProxyAsync(_cancellation.Token);
            ManagementSnapshot snapshot;
            if (_record.Protocol == 2)
            {
                var(host, port) = SolWorkspaceViewModel.ParseAddress(_record.Address, _record.Protocol);
                using var operation = new Core.OperationBudget(_record.Timeout?.Milliseconds ?? 15000);
                await using var connection = await IpmiConnection.OpenAsync(host, port, credential.Username, credential.Password, _record.Suite3Confirmed, _cancellation.Token, proxy, _record.Timeout, operation);
                snapshot = _section switch
                {
                    "sensors" => Sensors(await connection.GetSensorsAsync(_cancellation.Token)),
                    "sel" => await connection.GetSelAsync(_cancellation.Token),
                    "inventory" => await connection.GetFruAsync(_cancellation.Token),
                    "network" => await connection.GetNetworkAsync(_cancellation.Token),
                    _ => throw new ArgumentOutOfRangeException(),
                };
                await connection.DisposeAsync();
                snapshot = snapshot with
                {
                    LogoutStatus = connection.LastCloseStatus
                };
            }
            else
                snapshot = await RedfishManagement.ReadAsync(_record.Address, new(credential.Username, credential.Password), _record.SystemUri, _section, _record.CaFile ?? "", _record.CertPolicy, _cancellation.Token, _record.MinimumTls, proxy, _record.Timeout);
            if (_disposed)
                return;
            Items = snapshot.Items;
            Switches = snapshot.Switches;
            RaiseChanged(nameof(Switches));
            _loaded = true;
            Status = snapshot.Summary;
            if (Items.Count == 0)
                Status = Loc.T("manage.ipmi.noData");
            if (snapshot.Status != Bc.Ok)
                Status += " " + Bc.StatusText(snapshot.Status);
            if (snapshot.Truncated)
                Status += " " + Loc.F("manage.ipmi.truncated", ("count", Items.Count));
            if (snapshot.LogoutStatus != Bc.Ok)
            {
                _record.SessionUnconfirmed = true;
                Status += " " + Loc.T("error.sessionMayExist");
            }
        }
        catch (OperationCanceledException)when (_disposed)
        {
        }
        catch (Exception ex)
        {
            if (!_disposed)
                Status = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private static ManagementSnapshot Sensors(IpmiSensors snapshot) => new(snapshot.Sensors.Select(sensor => new ManagementItem(sensor.Name, new[] { new ManagementField(Loc.T("sensor.reading"), sensor.Reading?.ToString("G", CultureInfo.CurrentCulture) ?? Loc.T("common.unknown")), new ManagementField(Loc.T("sensor.units"), sensor.Units), new ManagementField(Loc.T("sensor.health"), Loc.T(sensor.Health switch
    {
        1 => "sensor.health.ok",
        2 => "sensor.health.warning",
        3 or 4 => "sensor.health.critical",
        _ => "sensor.health.unknown"
    })), new ManagementField(Loc.T("sensor.state"), sensor.DiscreteValidMask != 0 ? $"0x{sensor.DiscreteStates:X4} / 0x{sensor.DiscreteValidMask:X4}" : Bc.StatusText(sensor.Status)), }.Concat(sensor.Details).ToList())).ToList(), snapshot.Status, snapshot.Truncated);
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        _cancellation.Cancel();
    }
}
