using BControl.Core.Redfish;
using BControl.Core.Storage;
using System.Security.Cryptography;
using System.Text;

namespace BControl.Core.Media;

public sealed class RedfishMediaClient : IAsyncDisposable
{
    private readonly RedfishRuntime _runtime;
    private readonly CancellationTokenSource _lifetime;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _disposeLock = new();
    private RedfishSession? _session;
    private RedfishTaskPersistenceScope? _persistence;
    private Task? _disposeTask;

    private RedfishMediaClient(CancellationToken cancellation)
    {
        _lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        try { _runtime = RedfishRuntime.Create(); }
        catch { _lifetime.Dispose(); throw; }
    }

    public static async Task<RedfishMediaClient> ConnectAsync(string address, DeviceCredential credential,
        string caFile, uint certPolicy, uint timeoutMs, uint minimumTls, Socks5Connection? proxy,
        CancellationToken cancellation = default, Guid? endpointId = null)
    {
        cancellation.ThrowIfCancellationRequested();
        var client = new RedfishMediaClient(cancellation);
        if (endpointId is { } id) client._persistence = new(id, Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(address))));
        try
        {
            client._session = await RedfishSession.LoginAsync(client._runtime, address, credential,
                caFile, certPolicy, timeoutMs, client._lifetime.Token, minimumTls, proxy).ConfigureAwait(false);
            client._lifetime.Token.ThrowIfCancellationRequested();
            return client;
        }
        catch
        {
            await client.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    internal CancellationToken Cancellation => _lifetime.Token;

    public Task<RedfishMediaSnapshot> ReadAsync(uint timeoutMs, CancellationToken cancellation = default) =>
        RunAsync((session, token) => RedfishMediaDiscovery.ReadAsync(session, timeoutMs, token), cancellation);

    public Task<RedfishMediaWriteResult> InsertAsync(string uri, string image, bool writeProtected, uint timeoutMs,
        CancellationToken cancellation = default) => RunAsync(async (session, token) =>
        {
            return await session.InsertVirtualMediaWithResultAsync(uri, image, writeProtected, timeoutMs, token, _persistence).ConfigureAwait(false);
        }, cancellation);

    public async Task<bool> EjectAsync(string uri, uint timeoutMs, CancellationToken cancellation = default) =>
        (await EjectWithResultAsync(uri, timeoutMs, cancellation).ConfigureAwait(false)).Confirmed;

    public Task<(bool Confirmed, RedfishMediaWriteResult Write)> EjectWithResultAsync(string uri, uint timeoutMs,
        CancellationToken cancellation = default) => RunAsync(async (session, token) => {
            using var budget = new OperationBudget(timeoutMs);
            using var registration = token.Register(budget.Cancel);
            var result = await session.EjectVirtualMediaWithResultAsync(uri, budget.RemainingMilliseconds(), token, _persistence).ConfigureAwait(false);
            if (result.Pending) return (false, result);
            try {
                var current = await session.GetVirtualMediaAsync(uri, budget.RemainingMilliseconds(), token).ConfigureAwait(false);
                return (current.InsertedKnown && !current.Inserted, result);
            }
            catch (BControl.Core.Native.BcException error) {
                throw new BControl.Core.Native.BcException(error.Status, error.Message, error.HttpStatus, writeMayHaveTakenEffect: true);
            }
        }, cancellation);

    public Task<RedfishMediaTaskSnapshot> ResumeTaskAsync(RemoteMediaOperation operation, uint timeoutMs,
        CancellationToken cancellation = default) => RunAsync((session, token) => {
            if (_persistence == null || operation.Reference == null) throw new BControl.Core.Native.BcException(
                BControl.Core.Native.Bc.Unsupported, BControl.Core.Localization.Loc.T("media.operationUnconfirmed"));
            return session.ResumeMediaTaskAsync(operation.Reference, operation.MediaUri, operation.Action, _persistence, timeoutMs, token);
        }, cancellation);

    private async Task<T> RunAsync<T>(Func<RedfishSession, CancellationToken, Task<T>> operation,
        CancellationToken cancellation)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellation, _lifetime.Token);
        await _gate.WaitAsync(linked.Token).ConfigureAwait(false);
        try
        {
            linked.Token.ThrowIfCancellationRequested();
            return await operation(_session ?? throw new ObjectDisposedException(nameof(RedfishMediaClient)), linked.Token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    public ValueTask DisposeAsync()
    {
        lock (_disposeLock) { return new ValueTask(_disposeTask ??= DisposeCoreAsync()); }
    }

    private async Task DisposeCoreAsync()
    {
        _lifetime.Cancel();
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            try { if (_session != null) await _session.DisposeAsync().ConfigureAwait(false); }
            finally { _session = null; await _runtime.DisposeAsync().ConfigureAwait(false); }
        }
        finally { _gate.Release(); _lifetime.Dispose(); }
    }
}
