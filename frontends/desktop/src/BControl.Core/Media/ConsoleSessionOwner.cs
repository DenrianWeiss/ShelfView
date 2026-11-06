using BControl.Core.Kvm;

namespace BControl.Core.Media;
public sealed class ConsoleSessionOwner : IAsyncDisposable
{
    private readonly SemaphoreSlim _gate = new(1);
    private readonly Func<CancellationToken, Task<IKvmSession>> _connect;
    private readonly Func<string, CancellationToken, Task<ILocalMediaSession?>>? _independentMount;
    private readonly IMediaRecoveryStore? _recovery;
    private bool _restored;
    private bool _disposed;
    private IKvmSession? _session;
    private int _views;
    private bool _sharedMedia;
    public ILocalMediaSession? Media { get; private set; }

    private bool _cleanupPending;
    public bool CleanupPending { get => _cleanupPending || Media?.RemovalUnconfirmed == true && !Media.IsActive; private set => _cleanupPending = value; }
    public bool HasMedia => Media != null || CleanupPending;
    public bool HasDependentMedia => (Media?.DependsOnConsole ?? _sharedMedia) && HasMedia;

    public ConsoleSessionOwner(Func<Task<IKvmSession>> connect, Func<string, Task<ILocalMediaSession?>>? independentMount = null,
        IMediaRecoveryStore? recovery = null)
    {
        _connect = _ => connect();
        _independentMount = independentMount == null ? null : (path, _) => independentMount(path);
        _recovery = recovery;
    }

    public ConsoleSessionOwner(Func<CancellationToken, Task<IKvmSession>> connect,
        Func<string, CancellationToken, Task<ILocalMediaSession?>>? independentMount = null, IMediaRecoveryStore? recovery = null)
    {
        _connect = connect;
        _independentMount = independentMount;
        _recovery = recovery;
    }

    private async Task RestoreCoreAsync(CancellationToken cancellation)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_restored) return;
        if (_recovery != null) {
            _cleanupPending = await _recovery.ReadPendingAsync(cancellation).ConfigureAwait(false);
            if (_cleanupPending) _sharedMedia = true;
        }
        _restored = true;
    }
    public async Task RestoreAsync(CancellationToken cancellation = default)
    {
        await _gate.WaitAsync(cancellation).ConfigureAwait(false);
        try { await RestoreCoreAsync(cancellation).ConfigureAwait(false); }
        finally { _gate.Release(); }
    }
    public async Task VerifyRecoveryAsync(Func<CancellationToken, Task<bool>> readback, CancellationToken cancellation = default)
    {
        await _gate.WaitAsync(cancellation).ConfigureAwait(false);
        try {
            await RestoreCoreAsync(cancellation).ConfigureAwait(false);
            using var observation = _recovery == null ? null : await _recovery.ObserveAsync(cancellation).ConfigureAwait(false);
            var pending = CleanupPending || observation?.State.Pending == true;
            var localSource = Media is { } source && (source.IsActive || source.SourceAttached);
            var empty = await readback(cancellation).ConfigureAwait(false);
            cancellation.ThrowIfCancellationRequested();
            if (!pending || !empty || localSource) return;
            CleanupPending = true;
            if (observation != null) await observation.ClearAsync(cancellation).ConfigureAwait(false);
            CleanupPending = false;
            if (Media != null) { await Media.DisposeAsync().ConfigureAwait(false); Media = null; }
            await ReleaseUnusedAsync().ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }
    private async Task ClearRecoveryAsync(bool acknowledge = false)
    {
        CleanupPending = true;
        if (_recovery != null) {
            if (acknowledge) await _recovery.AcknowledgeAsync().ConfigureAwait(false);
            else await _recovery.ClearAsync().ConfigureAwait(false);
        }
        CleanupPending = false;
    }

    public async Task<IKvmSession> AcquireAsync(CancellationToken cancellation = default)
    {
        await _gate.WaitAsync(cancellation);
        try
        {
            await RestoreCoreAsync(cancellation);
            if (_session?.IsConnected != true)
            {
                if (Media == null && _recovery != null) {
                    CleanupPending = await _recovery.ReadPendingAsync(cancellation);
                    if (CleanupPending) _sharedMedia = true;
                }
                if (HasDependentMedia)
                    throw new InvalidOperationException(Localization.Loc.T("media.removalUnconfirmed"));
                if (_session != null)
                    await _session.DisposeAsync();
                _session = await _connect(cancellation);
            }

            _views++;
            return _session;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task ReleaseAsync()
    {
        await _gate.WaitAsync();
        try
        {
            _views = Math.Max(0, _views - 1);
            await ReleaseUnusedAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task ReleaseUnusedAsync()
    {
        if (_views != 0 || HasDependentMedia || _session == null)
            return;
        var session = _session;
        _session = null;
        await session.DisposeAsync();
    }

    public async Task MountAsync(string path, CancellationToken cancellation = default)
    {
        await _gate.WaitAsync(cancellation);
        var began = false;
        try
        {
            await RestoreCoreAsync(cancellation);
            if (HasMedia)
                throw new InvalidOperationException(Localization.Loc.T(CleanupPending && Media?.IsActive != true ? "media.removalUnconfirmed" : "media.alreadyMounted"));
            if (_recovery != null) {
                try { await _recovery.BeginAsync(cancellation); }
                catch (Native.BcException error) when (error.Status == Native.Bc.ConfirmationRequired) {
                    try { CleanupPending = await _recovery.ReadPendingAsync(CancellationToken.None); }
                    catch { CleanupPending = true; }
                    _sharedMedia = CleanupPending; throw;
                }
                catch { CleanupPending = true; _sharedMedia = true; throw; }
            }
            began = true;
            _sharedMedia = false;
            if (_session is ILocalMediaConsole { LocalMediaDetection.CanAttempt: true } existing)
            {
                _sharedMedia = true;
                Media = await existing.MountIsoAsync(path);
                return;
            }
            if (_independentMount != null && await _independentMount(path, cancellation)is { } independent)
            {
                Media = independent;
                return;
            }

            if (_session?.IsConnected != true)
            {
                if (_session != null)
                    await _session.DisposeAsync();
                _session = await _connect(cancellation);
            }

            if (_session is not ILocalMediaConsole { LocalMediaDetection.CanAttempt: true } console)
                throw new NotSupportedException(Native.Bc.StatusText(Native.Bc.Unsupported));
            _sharedMedia = true;
            Media = await console.MountIsoAsync(path);
        }
        catch (MediaStartupException ex)
        {
            Media = ex.Session;
            CleanupPending = true;
            throw;
        }
        catch
        {
            try {
                if (began && Media == null && !CleanupPending && _recovery != null) await ClearRecoveryAsync();
            }
            finally { await ReleaseUnusedAsync(); }
            throw;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> EjectAsync()
    {
        await _gate.WaitAsync();
        try
        {
            await RestoreCoreAsync(CancellationToken.None);
            if (Media == null)
                return !CleanupPending;
            try
            {
                var removed = await Media.EjectAsync();
                var closed = await Media.CloseMediaAsync();
                if (removed && closed) await ClearRecoveryAsync();
                else CleanupPending = true;
            }
            catch
            {
                CleanupPending = true;
                throw;
            }
            finally
            {
                if (!CleanupPending)
                    Media = null;
            }

            await ReleaseUnusedAsync();
            return !CleanupPending;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task ConfirmCleanupAsync()
    {
        await _gate.WaitAsync();
        try
        {
            await RestoreCoreAsync(CancellationToken.None);
            if (Media != null)
                await Media.DisposeAsync();
            Media = null;
            await ClearRecoveryAsync(acknowledge: true);
            await ReleaseUnusedAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync();
        try
        {
            if (_disposed) return;
            _disposed = true;
            try {
                if (Media != null) {
                    var confirmed = await Media.CloseMediaAsync();
                    if (confirmed) await ClearRecoveryAsync();
                    else CleanupPending = true;
                }
            }
            finally {
                Media = null;
                try { if (_session != null) await _session.DisposeAsync(); }
                finally { _session = null; }
            }
        }
        finally
        {
            _gate.Release();
        }
    }
}
