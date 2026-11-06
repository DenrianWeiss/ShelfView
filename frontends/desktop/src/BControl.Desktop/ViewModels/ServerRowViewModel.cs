using System.Collections.Concurrent;
using System.Globalization;
using BControl.Core;
using BControl.Core.Localization;
using BControl.Core.Native;
using BControl.Core.Redfish;
using BControl.Desktop.Services;

namespace BControl.Desktop.ViewModels;
/// <summary>关闭有挂载媒体页时的用户选择。</summary>
public enum MediaCloseChoice
{
    Cancel,
    KeepMounted,
    EjectAndClose
}

public enum MediaCloseResult
{
    Closed,
    Cancelled,
    KeptMounted,
    Ejected,
    EjectUnknown
}

public static class MediaCloseDecision
{
    /// <summary>
    /// 结果未知时保留远端可能挂载的状态，绝不返回“已弹出”。
    /// </summary>
    public static MediaCloseResult Resolve(MediaCloseChoice choice, bool hasActiveMount, bool ejectSucceeded, bool ejectOutcomeUnknown)
    {
        return choice switch
        {
            MediaCloseChoice.Cancel => MediaCloseResult.Cancelled,
            MediaCloseChoice.KeepMounted => hasActiveMount ? MediaCloseResult.KeptMounted : MediaCloseResult.Closed,
            MediaCloseChoice.EjectAndClose when !hasActiveMount => MediaCloseResult.Closed,
            MediaCloseChoice.EjectAndClose when ejectOutcomeUnknown => MediaCloseResult.EjectUnknown,
            MediaCloseChoice.EjectAndClose when ejectSucceeded => MediaCloseResult.Ejected,
            // 弹出失败：保留挂载状态，可重试。
            _ => MediaCloseResult.KeptMounted,
        };
    }
}

/// <summary>
/// 工作区注册表：(server_id, feature, resource_id) 唯一；重复打开只聚焦现有标签；
/// 媒体页每服务器唯一（单一所有者）；切换标签不断线（会话由注册表持有）。
/// </summary>
public sealed class WorkspaceRegistry
{
    private readonly ConcurrentDictionary<WorkspaceKey, WorkspaceTab> _tabs = new();
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _endpointQueues = new();
    private readonly ConcurrentDictionary<string, object> _mediaOwners = new();
    public IEnumerable<WorkspaceTab> Tabs => _tabs.Values.OrderBy(t => t.Key.ToString(), StringComparer.Ordinal);

    public event Action<WorkspaceTab>? TabAdded;
    public event Action<WorkspaceTab>? TabRemoved;
    /// <summary>同端点队列（概况/媒体操作串行用）。</summary>
    public SemaphoreSlim QueueForEndpoint(string endpointId) => (SemaphoreSlim)_mediaOwners.GetOrAdd(endpointId + ":queue", static _ => new SemaphoreSlim(1));
    public WorkspaceTab? Find(WorkspaceKey key) => _tabs.TryGetValue(key, out var tab) ? tab : null;
    public bool TryAdd(WorkspaceTab tab)
    {
        if (!_tabs.TryAdd(tab.Key, tab))
            return false;
        TabAdded?.Invoke(tab);
        return true;
    }

    public bool TryRemove(WorkspaceKey key, out WorkspaceTab? tab)
    {
        if (_tabs.TryRemove(key, out var removed))
        {
            tab = removed;
            TabRemoved?.Invoke(removed);
            return true;
        }

        tab = null;
        return false;
    }
}

/// <summary>服务器记录 + 实时概况状态的行视图模型。</summary>
public sealed class ServerRowViewModel : ViewModelBase
{
    private readonly ServerRecord _record;
    public ServerRecord Record => _record;

    public ServerRowViewModel(ServerRecord record)
    {
        _record = record;
        RefreshLanguage();
    }

    public string ServerId => _record.ServerId;
    public string Name => _record.Name;
    internal void RefreshName() => RaiseChanged(nameof(Name));
    public string Address => _record.Address;

    private OverviewFailure? _lastFailure;
    private bool _hasConnectionFailure;
    public bool HasConnectionFailure { get => _hasConnectionFailure; private set => SetProperty(ref _hasConnectionFailure, value); }

    private bool _isLoading;
    public bool IsLoading { get => _isLoading; set => SetProperty(ref _isLoading, value); }

    private string _status = Loc.T("overview.notRefreshed");
    public string Status { get => _status; set => SetProperty(ref _status, value); }

    private string _power = Loc.T("power.state.unknown");
    public string Power { get => _power; set => SetProperty(ref _power, value); }

    private string _brand = Loc.T("common.unknown");
    public string Brand { get => _brand; set => SetProperty(ref _brand, value); }

    private string? _cpuTemperature;
    public string? CpuTemperature { get => _cpuTemperature; set => SetProperty(ref _cpuTemperature, value); }
    private bool _temperatureFallback;
    public bool TemperatureFallback { get => _temperatureFallback; set => SetProperty(ref _temperatureFallback, value); }
    private string? _temperatureSource;
    public string? TemperatureSource { get => _temperatureSource; set => SetProperty(ref _temperatureSource, value); }

    private string? _normalMaximum;
    public string? NormalMaximum { get => _normalMaximum; set => SetProperty(ref _normalMaximum, value); }

    private string _connectivity = Loc.T("common.unknown");
    public string Connectivity { get => _connectivity; set => SetProperty(ref _connectivity, value); }

    private DateTimeOffset? _observedAt;
    public DateTimeOffset? ObservedAt { get => _observedAt; set => SetProperty(ref _observedAt, value); }

    private bool _expired;
    public bool Expired { get => _expired; set => SetProperty(ref _expired, value); }
    public bool CanKvm => _record.Capabilities.GraphicalConsole != false;
    public bool CanSol => !_record.Verified || _record.Capabilities.Sol;
    public bool CanMedia => true;

    public void ApplyOutcome(OverviewOutcome outcome)
    {
        switch (outcome)
        {
            case OverviewOutcome.Loading:
                IsLoading = true;
                Status = Loc.T("overview.refreshing");
                break;
            case OverviewOutcome.Value value:
                IsLoading = false;
                ApplyOverview(value.Overview);
                break;
            case OverviewOutcome.Failure failure:
                IsLoading = false;
                ApplyFailure(failure.Reason);
                break;
        }
    }

    private void ApplyOverview(DeviceOverview overview)
    {
        _lastFailure = null;
        HasConnectionFailure = false;
        var cached = new CachedOverview
        {
            ObservedAt = overview.ObservedAt,
            Expired = false,
            PowerState = overview.System.PowerState,
            RawPowerState = overview.System.RawPowerState,
            Manufacturer = overview.System.Manufacturer,
            Model = overview.System.Model,
            SystemName = overview.System.Name,
            CpuName = overview.Temperatures.Cpu?.Name,
            CpuCelsius = overview.Temperatures.Cpu?.Celsius,
            PrimaryTemperature = overview.Temperatures.Primary ?? overview.Temperatures.Cpu ?? overview.SharedTemperatures.Primary,
            NormalCelsius = overview.Temperatures.NormalMaximum?.Celsius,
            AlertCelsius = overview.Temperatures.AlertMaximum?.Celsius,
            TemperatureStatus = overview.TemperatureStatus,
            LogoutStatus = overview.LogoutStatus,
        };
        _record.Capabilities.GraphicalConsole = overview.System.GraphicalConsole;
        _record.LastOverview = cached;
        _record.SessionUnconfirmed = overview.LogoutStatus != Bc.Ok;
        Render(cached, Loc.T("overview.normal"));
    }

    private void ApplyFailure(OverviewFailure failure)
    {
        _lastFailure = failure;
        HasConnectionFailure = true;
        var cached = _record.LastOverview;
        var message = failure switch
        {
            OverviewFailure.CredentialsUnavailable => Loc.T("overview.credentialsUnavailable"),
            OverviewFailure.SessionUnconfirmed => Loc.T("overview.sessionUnconfirmed"),
            OverviewFailure.Unsupported => Loc.T("overview.unsupported"),
            OverviewFailure.Request request => Loc.F("overview.statusFailed", ("status", Bc.StatusText(request.Status))),
            _ => Loc.T("overview.failed"),
        };
        if (cached == null)
        {
            Expired = false;
            Status = message;
            Connectivity = Loc.T("overview.failed");
            return;
        }

        cached.Expired = true;
        Render(cached, message);
    }

    /// <summary>启动时渲染上次缓存的概况并标记为过期缓存。</summary>
    public void RenderCached(CachedOverview cached)
    {
        cached.Expired = true;
        Render(cached, Loc.T("common.cached"));
    }

    /// <summary>语言切换后重新求值已有状态，不重新访问设备。</summary>
    public void RefreshLanguage()
    {
        if (_lastFailure is { } failure)
        {
            ApplyFailure(failure);
            return;
        }

        if (_record.LastOverview is { } cached)
        {
            Render(cached, cached.Expired ? Loc.T("common.cached") : Loc.T("overview.normal"));
            return;
        }

        Status = Loc.T("overview.notRefreshed");
        Power = Loc.T("power.state.unknown");
        Brand = Loc.T("common.unknown");
        CpuTemperature = Loc.T("common.unknown");
        NormalMaximum = Loc.T("common.unknown");
        Connectivity = Loc.T("common.unknown");
    }

    private void Render(CachedOverview cached, string status)
    {
        Power = cached.PowerState switch
        {
            Bc.PowerOn => Loc.T("power.state.on"),
            Bc.PowerOff => Loc.T("power.state.off"),
            Bc.PoweringOn => Loc.T("power.state.poweringOn"),
            Bc.PoweringOff => Loc.T("power.state.poweringOff"),
            _ => Loc.T("power.state.unknown"),
        };
        Brand = string.IsNullOrEmpty(cached.Manufacturer) ? Loc.T("common.unknown") : cached.Manufacturer;
        if (!string.IsNullOrEmpty(cached.Model))
            Brand += " / " + cached.Model;
        var primary = cached.PrimaryTemperature;
        var celsius = primary?.Celsius ?? cached.CpuCelsius;
        CpuTemperature = celsius.HasValue ? Loc.F("overview.temperatureValue", ("value", celsius.Value.ToString("F1", CultureInfo.CurrentCulture))) : Loc.T("common.unknown");
        TemperatureFallback = primary?.ChassisFallback == true;
        TemperatureSource = (TemperatureFallback ? Loc.T("overview.chassisFallback") + ": " : "") + (primary?.Name ?? cached.CpuName ?? "");
        NormalMaximum = cached.NormalCelsius.HasValue ? Loc.F("overview.temperatureValue", ("value", cached.NormalCelsius.Value.ToString("F1", CultureInfo.CurrentCulture))) : Loc.T("common.unknown");
        ObservedAt = cached.ObservedAt;
        Expired = cached.Expired;
        Connectivity = status;
        Status = cached.Expired ? Loc.F("overview.cachedAt", ("status", status), ("time", cached.ObservedAt.ToLocalTime().ToString("T", CultureInfo.CurrentCulture))) : status;
        RaiseChanged(nameof(CanKvm));
        RaiseChanged(nameof(CanSol));
        RaiseChanged(nameof(CanMedia));
    }
}
