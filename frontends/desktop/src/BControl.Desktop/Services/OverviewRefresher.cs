using BControl.Core.Native;
using BControl.Core.Redfish;

namespace BControl.Desktop.Services;

public sealed record OverviewUpdate(string ServerId, OverviewOutcome Outcome);

public abstract record OverviewOutcome
{
    public sealed record Loading : OverviewOutcome;
    public sealed record Value(DeviceOverview Overview) : OverviewOutcome;
    public sealed record Failure(OverviewFailure Reason) : OverviewOutcome;
}

public abstract record OverviewFailure
{
    public sealed record CredentialsUnavailable : OverviewFailure;
    public sealed record SessionUnconfirmed : OverviewFailure;
    public sealed record Unsupported : OverviewFailure;
    public sealed record Request(uint Status, uint Http, uint? Cleanup) : OverviewFailure;
}

/// <summary>
/// 首页概况刷新：按端点分组串行、全局最多 4 组并发、上一轮未结束不叠加；
/// 注销未确认的端点进入隔离，直到用户重新验证。纯托管逻辑，便于单元测试。
/// </summary>
public sealed class OverviewRefresher
{
    public delegate Task<DeviceOverview> FetchDelegate(ServerRecord record, DeviceCredential credential, uint budgetMs, CancellationToken cancellation);

    private readonly FetchDelegate _fetch;
    private readonly object _lock = new();
    private bool _running;
    private readonly HashSet<string> _uncertainEndpoints = new(StringComparer.Ordinal);
    private readonly PendingReadCache<(string Server, string Endpoint, string User), DeviceCredential?> _credentialReads = new();

    public OverviewRefresher(FetchDelegate fetch) => _fetch = fetch;

    public bool IsEndpointUncertain(string endpointId)
    {
        lock (_lock) return _uncertainEndpoints.Contains(endpointId);
    }

    public void Quarantine(string endpointId)
    {
        lock (_lock) _uncertainEndpoints.Add(endpointId);
    }

    public void ClearQuarantine(string endpointId)
    {
        lock (_lock) _uncertainEndpoints.Remove(endpointId);
    }

    /// <summary>返回 false 表示上一轮仍在运行（不叠加新一轮）。</summary>
    public async Task<bool> RefreshAsync(
        IReadOnlyList<ServerRecord> records,
        Func<ServerRecord, CancellationToken, Task<DeviceCredential?>> credentialProvider,
        Func<OverviewUpdate, Task> update,
        CancellationToken cancellation = default)
    {
        lock (_lock)
        {
            if (_running) return false;
            _running = true;
        }
        try
        {
            foreach (var record in records.Where(r => r.SessionUnconfirmed))
                Quarantine(record.EndpointId);
            var groups = records.GroupBy(r => r.EndpointId, StringComparer.Ordinal).ToList();
            using var semaphore = new SemaphoreSlim(4);
            var tasks = groups.Select(async group =>
            {
                await semaphore.WaitAsync(cancellation).ConfigureAwait(false);
                try
                {
                    foreach (var record in group)
                    {
                        if (cancellation.IsCancellationRequested) return;
                        if (IsEndpointUncertain(record.EndpointId))
                        {
                            await update(new OverviewUpdate(record.ServerId,
                                new OverviewOutcome.Failure(new OverviewFailure.SessionUnconfirmed()))).ConfigureAwait(false);
                            continue;
                        }
                        await update(new OverviewUpdate(record.ServerId, new OverviewOutcome.Loading())).ConfigureAwait(false);
                        var started = Environment.TickCount64;
                        var budget = record.Timeout?.Milliseconds ?? 15000;
                        using var request = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
                        request.CancelAfter(TimeSpan.FromMilliseconds(budget));
                        OverviewOutcome outcome;
                        try
                        {
                            var secret = await _credentialReads.ReadAsync((record.ServerId, record.EndpointId, record.Username),
                                token => credentialProvider(record, token), request.Token).ConfigureAwait(false);
                            if (secret == null || secret.Username != record.Username)
                                throw new CredentialUnavailableException();
                            if (cancellation.IsCancellationRequested) return;
                            var elapsed = Environment.TickCount64 - started;
                            if (elapsed >= budget) throw new DiscoveryFailure(Bc.Timeout, 0, 0);
                            var overview = await _fetch(record, secret, (uint)(budget - elapsed), request.Token).ConfigureAwait(false);
                            var unconfirmed = overview.LogoutStatus != Bc.Ok;
                            outcome = new OverviewOutcome.Value(overview);
                            if (unconfirmed)
                            {
                                Quarantine(record.EndpointId);
                                await update(new OverviewUpdate(record.ServerId,
                                    new OverviewOutcome.Failure(new OverviewFailure.SessionUnconfirmed()))).ConfigureAwait(false);
                            }
                        }
                        catch (OperationCanceledException) when (request.IsCancellationRequested)
                        {
                            if (cancellation.IsCancellationRequested) return;
                            outcome = new OverviewOutcome.Failure(new OverviewFailure.Request(Bc.Timeout, 0, null));
                        }
                        catch (CredentialUnavailableException)
                        {
                            App.LogStatic("refresh 凭据不可用");
                            outcome = new OverviewOutcome.Failure(new OverviewFailure.CredentialsUnavailable());
                        }
                        catch (DiscoveryFailure failure)
                        {
                            App.LogStatic($"refresh DiscoveryFailure status={failure.Status} http={failure.HttpStatus} cleanup={failure.CleanupStatus}");
                            var cleanup = failure.CleanupStatus
                                ?? ((failure.AuthenticationFlags & 4) != 0 ? Bc.OutcomeUnknown : null);
                            var status = failure.Status == Bc.Cancelled && request.IsCancellationRequested && !cancellation.IsCancellationRequested
                                ? Bc.Timeout : failure.Status;
                            outcome = new OverviewOutcome.Failure(new OverviewFailure.Request(status, failure.HttpStatus, cleanup));
                        }
                        catch (BcException ex)
                        {
                            App.LogStatic($"refresh BcException status={ex.Status} http={ex.HttpStatus}");
                            var status = ex.Status == Bc.Cancelled && request.IsCancellationRequested && !cancellation.IsCancellationRequested
                                ? Bc.Timeout : ex.Status;
                            outcome = new OverviewOutcome.Failure(new OverviewFailure.Request(status, 0, null));
                        }
                        catch (Exception ex)
                        {
                            App.LogStatic($"refresh 其他异常 {ex.GetType().Name}\n{ex.StackTrace}");
                            outcome = new OverviewOutcome.Failure(new OverviewFailure.Request(Bc.IoError, 0, null));
                        }
                        if (outcome is OverviewOutcome.Failure { Reason: OverviewFailure.Request { Cleanup: { } uncertainCleanup } } && uncertainCleanup != Bc.Ok)
                            Quarantine(record.EndpointId);
                        if (cancellation.IsCancellationRequested) return;
                        await update(new OverviewUpdate(record.ServerId, outcome)).ConfigureAwait(false);
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            });
            await Task.WhenAll(tasks).ConfigureAwait(false);
            return true;
        }
        finally
        {
            lock (_lock) _running = false;
        }
    }

    private sealed class CredentialUnavailableException : Exception;
}
