using BControl.Core.Media;
using System.Collections.ObjectModel;
using BControl.Core;
using BControl.Core.Localization;
using BControl.Core.Redfish;
using BControl.Desktop.Services;

namespace BControl.Desktop.ViewModels;
public sealed class MediaWorkspaceViewModel : ViewModelBase, IAsyncDisposable
{
    private readonly ServerRecord _record;
    private readonly Func<Task<StoredCredential?>> _getCredential;
    private readonly ConsoleSessionOwner? _owner;
    private bool _showDiagnostics;
    public bool ShowDiagnostics { get => _showDiagnostics; private set => SetProperty(ref _showDiagnostics, value); }
    private bool _busy;
    public bool IsBusy { get => _busy; private set => SetProperty(ref _busy, value); }

    private string _localPath = "";
    public string LocalPath { get => _localPath; set => SetProperty(ref _localPath, value); }
    public string LocalName => _owner?.Media?.Name ?? "";
    public bool CleanupPending => _owner?.CleanupPending == true && _owner?.Media?.MediaSnapshot().Active != true;
    public string LocalStatistics => _owner?.Media?.Statistics is { } stats
        ? Loc.F("media.requests", ("count", stats.Requests), ("bytes", $"{stats.Bytes} B")) : "";

    private RedfishMediaClient? _client;
    private CancellationTokenSource? _connectionCancellation;
    private Task _lifecycle = Task.CompletedTask;
    private Task _polling = Task.CompletedTask;
    private bool _listingComplete;
    public ServerRecord Record => _record;
    public ObservableCollection<MediaDeviceRowViewModel> Devices { get; } = new();

    private string _status = Loc.T("kvm.notConnected");
    public string Status { get => _status; set => SetProperty(ref _status, value); }
    public bool RedfishPathAvailable => _record.Capabilities.MediaRedfish;

    private readonly RemoteMediaWorkspace _remote;
    public bool Owns(MediaDeviceRowViewModel device) => _remote.Owns(device.Uri);
    public bool HasActiveMount => _remote.HasActiveMount || _owner?.HasMedia == true;

    public MediaWorkspaceViewModel(ServerRecord record, Func<Task<StoredCredential?>> getCredential, IRemoteMediaStore remoteStore, ConsoleSessionOwner? owner = null)
    {
        _record = record;
        _owner = owner;
        _remote = new(remoteStore);
        _getCredential = getCredential;
    }

    public void RefreshLocal()
    {
        if (_owner?.Media?.MediaSnapshot().FailureMessage is { } error && !IsBusy)
        {
            ShowDiagnostics = true;
            Status = error + (_owner.CleanupPending ? " " + Loc.T("media.cleanupConfirm") : "");
        }
        RaiseChanged(nameof(HasActiveMount));
        RaiseChanged(nameof(LocalName));
        RaiseChanged(nameof(LocalStatistics));
        RaiseChanged(nameof(CleanupPending));
    }

    public async Task MountLocalAsync()
    {
        if (IsBusy || _owner == null || string.IsNullOrWhiteSpace(LocalPath))
            return;
        IsBusy = true;
        try
        {
            await _owner.MountAsync(LocalPath);
            ShowDiagnostics = false;
            Status = Loc.T(_owner.Media?.MountConfirmed == true ? "media.mounted" : "media.localReady");
        }
        catch (Exception ex)
        {
            ShowDiagnostics = true;
            Status = ex.Message;
        }
        finally
        {
            IsBusy = false;
            RefreshLocal();
        }
    }

    public async Task<bool> EjectLocalAsync()
    {
        if (IsBusy || _owner == null)
            return false;
        IsBusy = true;
        try
        {
            var confirmed = await _owner.EjectAsync();
            Status = Loc.T(confirmed ? "media.notMounted" : "media.cleanupConfirm");
            return confirmed;
        }
        catch (Exception ex)
        {
            ShowDiagnostics = true;
            Status = ex.Message;
            return false;
        }
        finally
        {
            IsBusy = false;
            RefreshLocal();
        }
    }

    public async Task ConfirmLocalCleanupAsync()
    {
        if (_owner == null || !CleanupPending)
            return;
        await _owner.ConfirmCleanupAsync();
        RefreshLocal();
    }

    public Task HideAsync() => DisconnectAsync();
    public Task ConnectAsync()
    {
        var previous = DisconnectAsync();
        var cancellation = new CancellationTokenSource();
        _connectionCancellation = cancellation;
        return _lifecycle = ConnectCoreAsync(previous, cancellation);
    }

    private async Task ConnectCoreAsync(Task previous, CancellationTokenSource cancellation)
    {
        RedfishMediaClient? client = null;
        try
        {
            await previous;
            cancellation.Token.ThrowIfCancellationRequested();
            await _remote.RestoreAsync(cancellation.Token);
            cancellation.Token.ThrowIfCancellationRequested();
            RaiseChanged(nameof(HasActiveMount));
            RefreshLocal();
            if (!RedfishPathAvailable) { Status = Loc.T("media.unverified"); return; }
            ShowDiagnostics = false;
            Status = Loc.T("kvm.connecting");
            var credential = await _getCredential().WaitAsync(cancellation.Token);
            cancellation.Token.ThrowIfCancellationRequested();
            if (credential == null) { ShowDiagnostics = true; Status = Loc.T("error.credentialsUnavailable"); return; }
            var proxy = await _record.ResolveProxyAsync(cancellation.Token);
            client = await RedfishMediaClient.ConnectAsync(_record.Address,
                new DeviceCredential(credential.Username, credential.Password), _record.CaFile ?? "",
                _record.CertPolicy, _record.Timeout?.Milliseconds ?? 5000, _record.MinimumTls, proxy, cancellation.Token, Guid.TryParse(_record.EndpointId, out var endpointId) ? endpointId : null);
            cancellation.Token.ThrowIfCancellationRequested();
            _client = client;
            client = null;
            await ReloadAsync();
            if (_client is { } connected) StartPolling(connected);
            if (ReferenceEquals(_connectionCancellation, cancellation) && !ShowDiagnostics && !_remote.HasPendingOperations && _listingComplete && Devices.Count > 0)
                Status = Loc.T("kvm.connected");
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (ReferenceEquals(_connectionCancellation, cancellation))
            {
                ShowDiagnostics = true;
                Status = Loc.F("kvm.connectionFailed", ("reason", ex.Message));
            }
        }
        finally { if (client != null) await client.DisposeAsync(); }
    }

    public async Task ReloadAsync()
    {
        if (_client == null)
            return;
        var client = _client;
        try
        {
            RedfishMediaSnapshot? snapshot = null;
            async Task<bool> Readback(CancellationToken cancellation)
            {
                snapshot = await _remote.ReadAsync(client, _record.Timeout?.Milliseconds ?? 30000, cancellation).ConfigureAwait(false);
                return snapshot.ConfirmsEmpty;
            }
            if (_owner != null) await _owner.VerifyRecoveryAsync(Readback);
            else await Readback(CancellationToken.None);
            if (!ReferenceEquals(_client, client) || snapshot == null) return;
            ApplySnapshot(snapshot);
            StartPolling(client);
        }
        catch (Exception ex)
        {
            if (!ReferenceEquals(_client, client)) return;
            ShowDiagnostics = true;
            Status = Loc.F("error.context", ("what", Loc.T("media.readFailed")), ("detail", ex.Message));
        }
    }

    private void ApplySnapshot(RedfishMediaSnapshot snapshot)
    {
        var current = Devices.ToDictionary(row => row.Uri, StringComparer.Ordinal);
        var next = snapshot.Devices.Select(device => {
            if (!current.TryGetValue(device.Uri, out var row)) row = new MediaDeviceRowViewModel(device);
            else row.Update(device);
            return row;
        }).ToArray();
        foreach (var row in Devices.Where(row => !next.Contains(row)).ToArray()) Devices.Remove(row);
        for (var index = 0; index < next.Length; index++) {
            var position = Devices.IndexOf(next[index]);
            if (position < 0) Devices.Insert(index, next[index]);
            else if (position != index) Devices.Move(position, index);
        }
        _listingComplete = snapshot.Complete;
        if (!snapshot.Complete) Status = Loc.T("media.readIncomplete");
        else if (Devices.Count == 0) Status = Loc.T("media.noDevices");
        else if (_remote.HasPendingOperations) Status = Loc.T("media.operationUnconfirmed");
        else Status = Loc.T("kvm.connected");
        RefreshLocal();
    }

    private void StartPolling(RedfishMediaClient client)
    {
        if (!_remote.HasPendingOperations || !_polling.IsCompleted || !ReferenceEquals(_client, client) ||
            _connectionCancellation is not { IsCancellationRequested: false } cancellation) return;
        _polling = PollAsync(client, cancellation.Token);
    }
    private async Task PollAsync(RedfishMediaClient client, CancellationToken cancellation)
    {
        try
        {
            await foreach (var snapshot in _remote.PollAsync(client, _record.Timeout?.Milliseconds ?? 15000, cancellation))
            {
                if (!ReferenceEquals(_client, client)) return;
                ApplySnapshot(snapshot);
            }
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!ReferenceEquals(_client, client)) return;
            ShowDiagnostics = true;
            Status = Loc.F("error.context", ("what", Loc.T("media.readFailed")), ("detail", ex.Message));
        }
    }

    public async Task<bool> MountAsync(VirtualMediaDevice device, string imageUrl, bool writeProtected)
    {
        if (_client == null || !device.CanInsert)
            return false;
        var client = _client;
        try
        {
            var confirmed = await _remote.InsertAsync(client, UriKey(device), imageUrl, writeProtected, _record.Timeout?.Milliseconds ?? 15000);
            if (!ReferenceEquals(_client, client)) return false;
            RaiseChanged(nameof(HasActiveMount));
            await ReloadAsync();
            if (!confirmed) Status = Loc.T("media.operationUnconfirmed");
            return confirmed;
        }
        catch (Exception ex)
        {
            if (!ReferenceEquals(_client, client)) return false;
            ShowDiagnostics = true;
            if (_remote.CurrentSnapshot is { } snapshot) ApplySnapshot(snapshot);
            StartPolling(client);
            RaiseChanged(nameof(HasActiveMount));
            Status = Loc.F("error.context", ("what", Loc.T("media.mountFailed")), ("detail", ex.Message));
            return false;
        }
    }

    /// <summary>弹出；返回 false 或结果未知时调用方必须保留挂载状态记录。</summary>
    public async Task<(bool Succeeded, bool OutcomeUnknown)> EjectAsync(VirtualMediaDevice device)
    {
        if (_client == null || !device.CanEject)
            return (false, false);
        var client = _client;
        try
        {
            var confirmed = await _remote.EjectAsync(client, UriKey(device), _record.Timeout?.Milliseconds ?? 15000);
            if (!ReferenceEquals(_client, client)) return (false, true);
            RaiseChanged(nameof(HasActiveMount));

            await ReloadAsync();
            return (confirmed, !confirmed);
        }
        catch (Exception ex)
        {
            if (!ReferenceEquals(_client, client)) return (false, true);
            ShowDiagnostics = true;
            if (_remote.CurrentSnapshot is { } snapshot) ApplySnapshot(snapshot);
            StartPolling(client);
            RaiseChanged(nameof(HasActiveMount));
            Status = Loc.F("error.context", ("what", Loc.T("media.ejectFailed")), ("detail", ex.Message));
            return (false, true); // 结果未知：保留挂载状态
        }
    }

    private static string UriKey(VirtualMediaDevice device) => device.Uri;
    public Task DisconnectAsync()
    {
        var cancellation = _connectionCancellation;
        _connectionCancellation = null;
        cancellation?.Cancel();
        var client = _client;
        _client = null;
        Devices.Clear();
        _listingComplete = false;
        Status = Loc.T("kvm.disconnected");
        return _lifecycle = DisconnectCoreAsync(_lifecycle, _polling, client, cancellation);
    }

    private async Task DisconnectCoreAsync(Task previous, Task polling, RedfishMediaClient? client,
        CancellationTokenSource? cancellation)
    {
        try
        {
            try { await previous; }
            finally {
                try { await polling; await _remote.DrainAsync(); }
                finally { if (client != null) await client.DisposeAsync(); }
            }
        }
        finally { cancellation?.Dispose(); }
    }

    public async ValueTask DisposeAsync() => await DisconnectAsync();
}
