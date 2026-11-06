using BControl.Core.Media;
using System.Collections.ObjectModel;
using BControl.Core.Ipmi;
using BControl.Core.Inventory;
using System.Globalization;
using BControl.Core.Localization;
using BControl.Core.Native;
using BControl.Core.Redfish;
using BControl.Desktop.Services;

namespace BControl.Desktop.ViewModels;
public sealed class MainViewModel : ViewModelBase, IAsyncDisposable
{
    public const uint OverviewRefreshIntervalMs = 30000;
    private readonly ServerStore _store;
    private readonly CredentialService _credentials;
    private readonly OverviewRefresher _refresher;
    private readonly HashSet<WorkspaceKey> _backgroundTabs = new();
    private readonly InventoryFile _inventory;
    private readonly Timer? _refreshTimer;
    private bool _disposed;
    private bool _automaticRefresh = true;
    private bool _discardInventoryOnShutdown;
    private Task _refreshCompletion = Task.CompletedTask;
    private Task? _shutdown;
    public bool IsOperational => !_disposed;
    public ServerStore VaultStore => _store;
    private readonly CancellationTokenSource _lifetime = new();
    private volatile bool _visible = true;
    private int _refreshGeneration;
    public ObservableCollection<ServerRowViewModel> Servers { get; } = new();
    public ObservableCollection<object> AllTabs { get; } = new();
    public ObservableCollection<WorkspaceTab> WorkspaceTabs { get; } = new();

    private readonly Dictionary<string, ConsoleSessionOwner> _consoleOwners = new(StringComparer.Ordinal);
    private readonly Dictionary<string, MediaWorkspaceViewModel> _hiddenMedia = new(StringComparer.Ordinal);
    public Func<uint, CancellationToken, Task<bool>>? ConfirmPrivate { get; set; }

    public async Task<bool> EjectLocalMediaAsync(string? serverId = null)
    {
        var confirmed = true;
        foreach (var pair in _consoleOwners.Where(pair => serverId == null || pair.Key == serverId))
        {
            if (pair.Value.Media is not { } media || !(media.IsActive || media.SourceAttached))
                continue;
            try
            {
                confirmed &= await pair.Value.EjectAsync();
            }
            catch (Exception ex)
            {
                StatusMessage = ex.Message;
                confirmed = false;
            }
        }

        return confirmed;
    }

    public bool ServerHasLocalMedia(string serverId) => _consoleOwners.TryGetValue(serverId, out var owner) && owner.HasMedia;
    public bool HasLocalMedia => _consoleOwners.Values.Any(owner => owner.Media is { } media && (media.IsActive || media.SourceAttached));

    public ConsoleSessionOwner ConsoleOwnerFor(ServerRecord record)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_consoleOwners.TryGetValue(record.ServerId, out var existing))
            return existing;
        record.ConfirmPrivate = (remaining, cancellation) => ConfirmPrivate?.Invoke(remaining, cancellation) ?? Task.FromResult(false);
        ConsoleSessionOwner? owner = null;
        owner = new ConsoleSessionOwner(async cancellation =>
        {
            var credential = await RequireCredentialAsync(record);
            if (credential == null)
                throw new InvalidOperationException(Loc.T("error.credentialsUnavailable"));
            return await BControl.Core.Kvm.RecoveringConsoleSession.ConnectAsync(() => ConsoleConnectionFactory.ConnectAsync(record, credential, cancellation), () => owner?.HasDependentMedia == true);
        }, async (path, cancellation) =>
        {
            var credential = await RequireCredentialAsync(record);
            if (credential == null)
                throw new InvalidOperationException(Loc.T("error.credentialsUnavailable"));
            return await ConsoleConnectionFactory.MountIndependentAsync(record, credential, path, cancellation);
        }, _store.MediaRecoveryFor(record));
        _consoleOwners.Add(record.ServerId, owner);
        return owner;
    }

    public WorkspaceRegistry Registry { get; } = new();

    private object? _selectedTab;
    public object? SelectedTab
    {
        get => _selectedTab;
        set
        {
            if (!SetProperty(ref _selectedTab, value ?? this))
                return;
            RaiseChanged(nameof(SelectedContent));
            RaiseChanged(nameof(SelectedWorkspace));
            RaiseChanged(nameof(IsHomeSelected));
        }
    }

    public object? SelectedContent => SelectedTab is WorkspaceTab tab ? tab.Content : SelectedTab;

    public bool IsHomeSelected => ReferenceEquals(SelectedTab, this);

    public WorkspaceTab? SelectedWorkspace
    {
        get => SelectedTab as WorkspaceTab;
        set
        {
            if (value != null)
                SelectedTab = value;
        }
    }

    private string _statusMessage = "";
    public string StatusMessage { get => _statusMessage; set => SetProperty(ref _statusMessage, value); }

    private bool _isRefreshing;
    public bool IsRefreshing { get => _isRefreshing; set => SetProperty(ref _isRefreshing, value); }
    public string Title => Loc.T("overview.homeTitle");
    public bool CanClose => false;
    public IReadOnlyList<LanguageOption> Languages => Loc.Instance.Languages;

    public LanguageOption SelectedLanguage
    {
        get => Loc.Instance.Languages.First(language => language.Tag == Loc.Instance.Language);
        set
        {
            if (value is not null && value.Tag != Loc.Instance.Language)
                Loc.Instance.Language = value.Tag;
        }
    }

    public MainViewModel(ServerStore store, CredentialService credentials, InventoryFile? inventory = null, bool automaticRefresh = true)
    {
        _automaticRefresh = automaticRefresh;
        _store = store;
        _credentials = credentials;
        BControl.Desktop.App.LogStatic("加载清单");
        _inventory = inventory ?? store.LoadAsync().GetAwaiter().GetResult();
        BControl.Desktop.App.LogStatic("清单已加载");
        BControl.Desktop.App.LogStatic("创建 Refresher");
        _refresher = new OverviewRefresher(FetchOverviewAsync);
        AllTabs.Add(this);
        SelectedTab = this;
        Loc.Instance.LanguageChanged += OnLanguageChanged;
        Registry.TabAdded += tab =>
        {
            var activate = !_backgroundTabs.Remove(tab.Key);
            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                AllTabs.Add(tab);
                WorkspaceTabs.Add(tab);
                if (activate) SelectedTab = tab;
            });
        };
        Registry.TabRemoved += tab =>
        {
            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                var index = WorkspaceTabs.IndexOf(tab);
                WorkspaceTabs.Remove(tab);
                if (ReferenceEquals(SelectedTab, tab))
                    SelectedTab = WorkspaceTabs.Count == 0 ? this : WorkspaceTabs[Math.Clamp(index, 0, WorkspaceTabs.Count - 1)];
                AllTabs.Remove(tab);
            });
        };
        foreach (var record in _inventory.Servers)
        {
            record.ReadProxyCredential = _credentials.ReadAsync;
            var row = new ServerRowViewModel(record);
            if (record.LastOverview is { } cached)
                row.RenderCached(cached);
            Servers.Add(row);
        }

        _refreshTimer = new Timer(_ =>
        {
            if (_visible && _automaticRefresh && IsHomeSelected && !_disposed)
                Avalonia.Threading.Dispatcher.UIThread.Post(() => _ = RefreshAsync());
        }, null, OverviewRefreshIntervalMs, OverviewRefreshIntervalMs);
    }

    public void SetVisible(bool visible) => _visible = visible;
    public async Task RefreshAsync()
    {
        if (IsRefreshing || _disposed)
            return;
        _automaticRefresh = true;
        var refreshDone = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _refreshCompletion = refreshDone.Task;
        IsRefreshing = true;
        var generation = Interlocked.Increment(ref _refreshGeneration);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        try
        {
            var records = Servers.Select(r => r.Record).ToList();
            await _refresher.RefreshAsync(records, GetCredentialAsync, update =>
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    if (generation != _refreshGeneration)
                        return;
                    var row = Servers.FirstOrDefault(r => r.ServerId == update.ServerId);
                    row?.ApplyOutcome(update.Outcome);
                });
                return Task.CompletedTask;
            }, cts.Token);
            StatusMessage = Loc.F("overview.refreshedAt", ("time", DateTimeOffset.Now.ToString("T", CultureInfo.CurrentCulture)));
        }
        catch (OperationCanceledException)
        {
            StatusMessage = Loc.T("overview.refreshCancelled");
        }
        finally
        {
            try { if (!_disposed) await SaveAsync(); }
            finally { IsRefreshing = false; refreshDone.TrySetResult(); }
        }
    }

    private async Task<DeviceCredential?> GetCredentialAsync(ServerRecord record, CancellationToken cancellation)
    {
        var result = await _credentials.ReadAsync(record.CredentialRef, record.Username, cancellation).ConfigureAwait(false);
        return result.Credential is { } credential ? new DeviceCredential(credential.Username, credential.Password) : null;
    }

    private static async Task<DeviceOverview> FetchOverviewAsync(ServerRecord record, DeviceCredential credential, uint budgetMs, CancellationToken cancellation)
    {
        using var operation = new BControl.Core.OperationBudget(budgetMs);
        var proxy = await record.ResolveProxyAsync(cancellation).ConfigureAwait(false);
        if (record.Protocol == 2)
        {
            var(host, port) = SolWorkspaceViewModel.ParseAddress(record.Address, record.Protocol);
            await using var connection = await IpmiConnection.OpenAsync(host, port, credential.Username, credential.Password, record.Suite3Confirmed, cancellation, proxy, record.Timeout, operation).ConfigureAwait(false);
            var capabilities = await connection.ProbeAsync().ConfigureAwait(false);
            var chassis = await connection.GetChassisStatusAsync().ConfigureAwait(false);
            var temperatures = new TemperatureSummary(null, null, null);
            uint temperatureStatus;
            try
            {
                var sensors = await connection.GetSensorsAsync(cancellation, temperaturesOnly: true).ConfigureAwait(false);
                temperatures = IpmiOverview.Summarize(sensors.Sensors);
                temperatureStatus = sensors.Status;
            }
            catch (BcException ex)
            {
                temperatureStatus = ex.Status;
            }

            var cached = record.LastOverview;
            var manufacturer = cached?.Manufacturer ?? "";
            var model = cached?.Model ?? "";
            if (manufacturer.Length == 0 || model.Length == 0)
            {
                try
                {
                    var identity = await connection.GetIdentityAsync(cancellation).ConfigureAwait(false);
                    if (manufacturer.Length == 0)
                        manufacturer = identity.Manufacturer;
                    if (model.Length == 0)
                        model = identity.Model;
                }
                catch (BcException)
                {
                }
            }

            await connection.DisposeAsync().ConfigureAwait(false);
            return new DeviceOverview(new DiscoveredSystem("", record.Name, manufacturer, model, "", chassis.PowerState, "") { GraphicalConsole = capabilities.GraphicalConsole }, DateTimeOffset.Now, temperatures, new TemperatureSummary(null, null, null), temperatureStatus, 0, connection.LastCloseStatus);
        }

        return await DiscoveryService.OverviewAsync(record.Address, credential, record.SystemUri, record.CaFile ?? "", record.CertPolicy, cancellation, operation.RemainingMilliseconds(), record.MinimumTls, proxy, record.Timeout).ConfigureAwait(false);
    }

    public async Task AddServerAsync(ServerRecord record, StoredCredential credential, bool saveVerified, StoredCredential? proxyCredential = null)
    {
        using var edit = BeginEdit();
        // 元数据与凭据进入同一 Vault；凭据保存失败时仅保留进程副本。
        if (_inventory.Servers.Any(existing => existing.Address == record.Address && existing.SystemUri == record.SystemUri))
            throw new InvalidOperationException(Loc.T("server.duplicate"));
        if (record.Proxy is { } proxy)
        {
            _ = new BControl.Core.Socks5Connection(proxy.Host, proxy.Port, proxyCredential?.Username ?? "", proxyCredential?.Password ?? "");
            if ((proxy.CredentialRef != null) != (proxyCredential != null) || proxy.Username != (proxyCredential?.Username ?? ""))
                throw new InvalidOperationException(Loc.T("proxy.credentialUnavailable"));
        }
        record.ReadProxyCredential = _credentials.ReadAsync;
        record.CredentialRef = record.ServerId;
        var updated = _inventory.Servers.Append(record).ToList();
        await _store.SaveAsync(new InventoryFile { Version = _inventory.Version, Servers = updated });
        _inventory.Servers = updated;
        var persistence = await _credentials.StoreAsync(record.CredentialRef, credential, CancellationToken.None);
        if (record.Proxy?.CredentialRef is { } proxyReference && proxyCredential != null)
            if (await _credentials.StoreAsync(proxyReference, proxyCredential) == CredentialPersistence.ProcessOnly)
                persistence = CredentialPersistence.ProcessOnly;
        var row = new ServerRowViewModel(record);
        Servers.Add(row);
        if (persistence == CredentialPersistence.ProcessOnly)
        {
            record.VerificationErrorKey = "server.credentialSaveUnavailable";
            record.VerificationError = Loc.T("server.credentialSaveUnavailable");
            StatusMessage = Loc.T("server.addedProcessOnly");
        }
        else
        {
            StatusMessage = Loc.T("server.added");
        }

        await SaveAsync();
    }

    public async Task ImportAsync(IReadOnlyList<InventoryEntry> entries, bool updateNames)
    {
        using var edit = BeginEdit();
        var merged = InventoryMerge.Apply(_inventory.Servers, entries, updateNames);
        await _store.SaveAsync(new InventoryFile { Version = _inventory.Version, Servers = merged });
        var current = _inventory.Servers.ToDictionary(record => record.ServerId, StringComparer.Ordinal);
        _inventory.Servers = merged.Select(record =>
        {
            if (!current.TryGetValue(record.ServerId, out var existing))
                return record;
            existing.Name = record.Name;
            return existing;
        }).ToList();
        Servers.Clear();
        foreach (var record in _inventory.Servers)
        {
            record.ReadProxyCredential = _credentials.ReadAsync;
            var row = new ServerRowViewModel(record);
            if (record.LastOverview is { } cached)
                row.RenderCached(cached);
            Servers.Add(row);
        }

        foreach (var tab in Registry.Tabs)
            tab.RefreshLanguage();
    }

    public async Task DeleteServerAsync(ServerRowViewModel row)
    {
        using var edit = BeginEdit();
        if (ServerHasLocalMedia(row.ServerId))
            throw new InvalidOperationException(Loc.T("media.cleanupConfirm"));
        if (_hiddenMedia.Remove(row.ServerId, out var hidden))
            await hidden.DisposeAsync();
        foreach (var tab in Registry.Tabs.Where(t => t.Key.ServerId == row.ServerId).ToList())
            await CloseWorkspaceAsync(tab);
        var remaining = _inventory.Servers.Where(r => r.ServerId != row.ServerId).ToList();
        await _store.SaveAsync(new InventoryFile { Version = _inventory.Version, Servers = remaining });
        _inventory.Servers = remaining;
        Servers.Remove(row);
        if (!remaining.Any(r => r.CredentialRef == row.Record.CredentialRef || r.Proxy?.CredentialRef == row.Record.CredentialRef))
            await _credentials.DeleteAsync(row.Record.CredentialRef);
        if (row.Record.Proxy?.CredentialRef is { } proxyReference &&
            !remaining.Any(r => r.CredentialRef == proxyReference || r.Proxy?.CredentialRef == proxyReference))
            await _credentials.DeleteAsync(proxyReference);
    }

    public Func<ServerRecord, bool, Task<StoredCredential?>>? PromptCredential { get; set; }

    public async Task<StoredCredential?> RequireCredentialAsync(ServerRecord record, bool authenticationFailed = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var saved = await _credentials.ReadAsync(record.CredentialRef, record.Username);
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!authenticationFailed && saved.Credential != null)
            return saved.Credential;
        var prompted = PromptCredential == null ? null : await PromptCredential(record, authenticationFailed);
        ObjectDisposedException.ThrowIf(_disposed, this); return prompted;
    }

    public async Task SaveCredentialAsync(ServerRecord record, StoredCredential credential, bool persist)
    {
        using var edit = BeginEdit();
        var previousUser = record.Username;
        var previousRef = record.CredentialRef;
        record.Username = credential.Username;
        if (string.IsNullOrEmpty(record.CredentialRef))
            record.CredentialRef = Guid.NewGuid().ToString("N");
        try
        {
            await SaveAsync();
        }
        catch
        {
            record.Username = previousUser;
            record.CredentialRef = previousRef;
            throw;
        }

        if (persist)
        {
            var persistence = await _credentials.StoreAsync(record.CredentialRef, credential);
            if (persistence == CredentialPersistence.ProcessOnly)
                StatusMessage = Loc.T("server.credentialSaveUnavailable");
        }
        else
            _credentials.StoreForProcess(record.CredentialRef, credential);
    }

    public Task SaveProxyAsync(ServerRecord record, string? host, ushort port, StoredCredential? credential) =>
        SaveProxyAsync(record, host, port, credential, record.Timeout);
    public Task SaveProxyAsync(ServerRecord record, string? host, ushort port, StoredCredential? credential, BControl.Core.HostTimeout? timeout) =>
        SaveConnectionAsync(record, host, port, credential, timeout, record.CaFile, record.CertPolicy, record.MinimumTls);

    internal async Task SaveConnectionAsync(ServerRecord record, string? host, ushort port, StoredCredential? credential,
        BControl.Core.HostTimeout? timeout, string? caFile, uint certPolicy, uint minimumTls,
        string? name = null, bool keepProxy = false)
    {
        using var edit = BeginEdit();
        var previous = record.Proxy;
        var previousSettings = (record.Timeout, record.CaFile, record.CertPolicy, record.MinimumTls, record.Name);
        var next = keepProxy ? previous : null;
        if (!keepProxy && host != null)
        {
            _ = new BControl.Core.Socks5Connection(host, port, credential?.Username ?? "", credential?.Password ?? "");
            if (credential != null && credential.Username.Length == 0)
                throw new InvalidOperationException(Loc.T("proxy.credentialUnavailable"));
            next = new ServerProxy { Host = host, Port = port, Username = credential?.Username ?? "",
                CredentialRef = credential == null ? null : Guid.NewGuid().ToString("N") };
        }
        record.Proxy = next;
        (record.Timeout, record.CaFile, record.CertPolicy, record.MinimumTls) = (timeout, caFile, certPolicy, minimumTls);
        record.Name = name ?? record.Name;
        try { await SaveAsync(); }
        catch
        {
            record.Proxy = previous;
            (record.Timeout, record.CaFile, record.CertPolicy, record.MinimumTls, record.Name) = previousSettings;
            throw;
        }
        if (record.Name != previousSettings.Name)
        {
            Servers.FirstOrDefault(row => ReferenceEquals(row.Record, record))?.RefreshName();
            foreach (var tab in Registry.Tabs.Where(tab => tab.Key.ServerId == record.ServerId))
                tab.RefreshTitle();
        }
        if (!keepProxy && next?.CredentialRef is { } reference && credential != null)
        {
            var persistence = await _credentials.StoreAsync(reference, credential);
            if (persistence == CredentialPersistence.ProcessOnly)
                StatusMessage = Loc.T("server.credentialSaveUnavailable");
        }
        if (previous?.CredentialRef is { } oldReference &&
            !_inventory.Servers.Any(r => r.CredentialRef == oldReference || r.Proxy?.CredentialRef == oldReference))
            await _credentials.DeleteAsync(oldReference);
        Interlocked.Increment(ref _refreshGeneration);
    }

    public Func<Task<StoredCredential?>> CredentialProviderFor(ServerRecord record) => () => RequireCredentialAsync(record);
    /// <summary>打开工作区标签；已存在时返回现有标签（由调用方聚焦）。</summary>
    public async Task<WorkspaceTab> OpenWorkspaceAsync(ServerRecord record, WorkspaceFeature feature, bool selectExisting = true)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (feature == WorkspaceFeature.Kvm && record.Capabilities.GraphicalConsole == false)
            feature = WorkspaceFeature.Sol;
        var key = new WorkspaceKey(record.ServerId, feature);
        var existing = Registry.Find(key);
        if (existing != null)
        {
            if (selectExisting) SelectedTab = existing;
            return existing;
        }

        var owner = feature == WorkspaceFeature.Sol ? null : ConsoleOwnerFor(record);
        if (owner != null) await owner.RestoreAsync(_lifetime.Token);
        ObjectDisposedException.ThrowIf(_disposed, this);
        existing = Registry.Find(key);
        if (existing != null) { if (selectExisting) SelectedTab = existing; return existing; }
        object content = feature switch
        {
            WorkspaceFeature.Kvm => new KvmWorkspaceViewModel(record, CredentialProviderFor(record), owner),
            WorkspaceFeature.Sol => new SolWorkspaceViewModel(record, CredentialProviderFor(record)),
            WorkspaceFeature.Media => _hiddenMedia.Remove(record.ServerId, out var retained) ? retained : new MediaWorkspaceViewModel(record, CredentialProviderFor(record), _store.RemoteMediaFor(record), owner),
            _ => throw new ArgumentOutOfRangeException(nameof(feature)),
        };
        var titleKey = feature switch
        {
            WorkspaceFeature.Kvm => "workspace.kvmTab",
            WorkspaceFeature.Sol => "workspace.solTab",
            WorkspaceFeature.Media => "workspace.mediaTab",
            _ => "server.name",
        };
        var tab = new WorkspaceTab(key, () => Loc.F(titleKey, ("name", record.Name)), content);
        if (!selectExisting) _backgroundTabs.Add(key);
        Registry.TryAdd(tab);
        if (content is KvmWorkspaceViewModel kvm)
        {
            kvm.OpenMedia = async () => (await OpenWorkspaceAsync(record, WorkspaceFeature.Media, selectExisting: false)).Content as MediaWorkspaceViewModel;
            kvm.RecoverAuthentication = async () => await RequireCredentialAsync(record, true) != null;
            _ = kvm.ConnectAsync();
        }

        if (content is MediaWorkspaceViewModel media)
            _ = media.ConnectAsync();
        if (content is SolWorkspaceViewModel sol)
        {
            sol.RecoverAuthentication = async () => await RequireCredentialAsync(record, true) != null;
            _ = sol.ConnectAsync();
        }

        return tab;
    }

    /// <summary>关闭标签；媒体页有挂载时由调用方先弹保留/弹出/取消对话框。</summary>
    public async Task CloseWorkspaceAsync(WorkspaceTab tab)
    {
        if (tab.Content is MediaWorkspaceViewModel closingMedia)
            foreach (var console in Registry.Tabs.Select(item => item.Content).OfType<KvmWorkspaceViewModel>())
                if (ReferenceEquals(console.Media, closingMedia)) { console.ShowMedia = false; console.Media = null; }

        if (tab.Content is MediaWorkspaceViewModel { HasActiveMount: true } media)
        {
            _hiddenMedia[tab.Key.ServerId] = media;
            await media.HideAsync();
        }
        else if (tab.Content is IAsyncDisposable disposable)
            await disposable.DisposeAsync();
        Registry.TryRemove(tab.Key, out _);
    }

    private void OnLanguageChanged()
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            RaiseChanged(nameof(SelectedLanguage));
            RaiseChanged(nameof(Title));
            foreach (var row in Servers)
                row.RefreshLanguage();
            foreach (var tab in AllTabs.OfType<WorkspaceTab>())
                tab.RefreshLanguage();
        });
    }

    private int _activeEdits;
    private Task _editCompletion = Task.CompletedTask;
    private TaskCompletionSource? _editsDone;
    private IDisposable BeginEdit()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_activeEdits++ == 0) {
            _editsDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
            _editCompletion = _editsDone.Task;
        }
        return new EditScope(this);
    }
    private sealed class EditScope(MainViewModel owner) : IDisposable
    {
        public void Dispose()
        {
            if (--owner._activeEdits == 0) owner._editsDone!.TrySetResult();
        }
    }
    private Task SaveAsync() => _store.SaveAsync(_inventory);
    public bool SupportsMasterPasswordChange => _store.SupportsMasterPasswordChange;
    public async Task ChangeMasterPasswordAsync(string password, CancellationToken cancellation = default)
    {
        using var edit = BeginEdit();
        await _store.ChangeMasterPasswordAsync(password, cancellation);
    }
    public ValueTask DisposeAsync() => new(StopAsync(false));
    public Task StopForVaultChangeAsync() => StopAsync(true);
    private Task StopAsync(bool discardInventory)
    {
        _discardInventoryOnShutdown |= discardInventory;
        if (_shutdown is { IsCompletedSuccessfully: true } || _shutdown is { IsCompleted: false }) return _shutdown;
        return _shutdown = StopCoreAsync();
    }
    private async Task StopCoreAsync()
    {
        if (!_disposed) {
            _disposed = true; RaiseChanged(nameof(IsOperational));
            _lifetime.Cancel(); Interlocked.Increment(ref _refreshGeneration);
            Loc.Instance.LanguageChanged -= OnLanguageChanged; _refreshTimer?.Dispose();
        }
        await _refreshCompletion;
        await _editCompletion;
        var errors = new List<Exception>();
        try {
            foreach (var tab in Registry.Tabs.ToList()) {
                try {
                    if (tab.Content is IAsyncDisposable content) await content.DisposeAsync();
                    Registry.TryRemove(tab.Key, out _);
                } catch (Exception error) { errors.Add(error); }
            }
            foreach (var (id, media) in _hiddenMedia.ToArray()) {
                try { await media.DisposeAsync(); _hiddenMedia.Remove(id); }
                catch (Exception error) { errors.Add(error); }
            }
            foreach (var (id, owner) in _consoleOwners.ToArray()) {
                try { await owner.DisposeAsync(); _consoleOwners.Remove(id); }
                catch (Exception error) { errors.Add(error); }
            }
            if (errors.Count != 0) throw new AggregateException(errors);
            if (!_discardInventoryOnShutdown) await SaveAsync();
        }
        finally { _credentials.ClearProcessCredentials(); }
    }
}
