using BControl.Core.Redfish;
using BControl.Core.Native;
using System.Runtime.CompilerServices;
using System.Collections.Concurrent;
using BControl.Core.Storage;

namespace BControl.Core.Media;

public sealed class RemoteMediaWorkspace(IRemoteMediaStore store)
{
    private readonly IRemoteMediaStore _store = store ?? throw new ArgumentNullException(nameof(store));
    private readonly SemaphoreSlim _gate = new(1, 1);
    private RemoteMediaOperation[] _operations = [];
    private RedfishMediaSnapshot? _snapshot;
    private readonly ConcurrentDictionary<string, long> _nextPoll = new(StringComparer.Ordinal);
    private readonly HashSet<string> _ownedOperations = new(StringComparer.Ordinal);
    public bool HasPendingOperations => Volatile.Read(ref _operations).Any(item => item.Phase is RemoteMediaPhase.Submitting or RemoteMediaPhase.Accepted);
    public bool HasActiveMount => Volatile.Read(ref _operations).Length > 0;
    public bool Owns(string uri) => Volatile.Read(ref _operations).Any(item => item.MediaUri == uri);
    public RedfishMediaSnapshot? CurrentSnapshot => Volatile.Read(ref _snapshot) is { } snapshot ? WithSourceState(snapshot) : null;

    public async Task DrainAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        _gate.Release();
    }

    public async Task RestoreAsync(CancellationToken cancellation = default)
    {
        await _gate.WaitAsync(cancellation).ConfigureAwait(false);
        try { await RestoreCoreAsync(cancellation).ConfigureAwait(false); }
        finally { _gate.Release(); }
    }
    private async Task RestoreCoreAsync(CancellationToken cancellation)
    {
        Volatile.Write(ref _operations, (await _store.ReadAsync(cancellation).ConfigureAwait(false)).ToArray());
        var current = _operations.Select(item => item.OperationId).ToHashSet(StringComparer.Ordinal);
        _ownedOperations.IntersectWith(current);
        foreach (var id in _nextPoll.Keys) if (!current.Contains(id)) _nextPoll.TryRemove(id, out _);
    }
    private async Task<RemoteMediaOperation?> UpdateAsync(string uri, string? expected, RemoteMediaAction action,
        RemoteMediaPhase phase, CancellationToken cancellation, byte[]? reference = null, string? source = null)
    {
        var result = await _store.UpdateAsync(uri, expected, action, phase, reference, cancellation, source).ConfigureAwait(false);
        Volatile.Write(ref _operations, _operations.Where(item => item.MediaUri != uri).Concat(result == null ? [] : new[] { result }).ToArray());
        if (phase == RemoteMediaPhase.Submitting && result != null) _ownedOperations.Add(result.OperationId);
        if (phase == RemoteMediaPhase.Cleared && expected != null) { _ownedOperations.Remove(expected); _nextPoll.TryRemove(expected, out _); }
        return result;
    }
    private async Task RejectAsync(RemoteMediaOperation entry)
    {
        var restored = await _store.RejectAsync(entry.MediaUri, entry.OperationId, CancellationToken.None).ConfigureAwait(false);
        Volatile.Write(ref _operations, _operations.Where(item => item.MediaUri != entry.MediaUri).Concat(restored == null ? [] : new[] { restored }).ToArray());
        _ownedOperations.Remove(entry.OperationId); _nextPoll.TryRemove(entry.OperationId, out _);
        if (restored != null) {
            _ownedOperations.Add(restored.OperationId);
            if (restored.Phase == RemoteMediaPhase.Accepted) _nextPoll[restored.OperationId] = Environment.TickCount64 + 1000;
        }
    }
    private async Task<T> SubmitAsync<T>(RemoteMediaOperation entry, OperationBudget budget, CancellationToken cancellation,
        Func<uint, Task<T>> submit)
    {
        var dispatched = false;
        try {
            var remaining = budget.RemainingMilliseconds();
            cancellation.ThrowIfCancellationRequested();
            dispatched = true;
            return await submit(remaining).ConfigureAwait(false);
        }
        catch (Exception error) when (!dispatched || error is BcException { WriteMayHaveTakenEffect: false }) {
            try { await RejectAsync(entry).ConfigureAwait(false); }
            catch (Exception cleanup) { throw new AggregateException(error, cleanup); }
            throw;
        }
    }
    public async Task<RedfishMediaSnapshot> ReadAsync(RedfishMediaClient client, uint timeoutMs,
        CancellationToken cancellation = default)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellation, client.Cancellation);
        cancellation = lifetime.Token;
        await _gate.WaitAsync(cancellation).ConfigureAwait(false);
        try
        {
            using var budget = new OperationBudget(timeoutMs);
            using var registration = cancellation.Register(budget.Cancel);
            await RestoreCoreAsync(cancellation).ConfigureAwait(false);
            var observed = _operations;
            var tasks = new Dictionary<string, RedfishMediaTaskSnapshot>(StringComparer.Ordinal);
            foreach (var entry in observed.Where(item => (item.Phase is RemoteMediaPhase.Submitting or RemoteMediaPhase.Accepted) && item.Reference != null))
            {
                if (_nextPoll.TryGetValue(entry.OperationId, out var due) && due > Environment.TickCount64) continue;
                try {
                    var task = await client.ResumeTaskAsync(entry, budget.RemainingMilliseconds(), cancellation).ConfigureAwait(false);
                    tasks[entry.OperationId] = task;
                    _nextPoll[entry.OperationId] = RedfishTaskDelay.Due(task.RetryAfter, Environment.TickCount64, DateTimeOffset.UtcNow);
                }
                catch (BcException error) when (error.Status is not (Bc.Timeout or Bc.Cancelled)) { }
            }
            var snapshot = await client.ReadAsync(budget.RemainingMilliseconds(), cancellation).ConfigureAwait(false);
            Volatile.Write(ref _snapshot, snapshot);
            if (!snapshot.Complete) return WithSourceState(snapshot);
            foreach (var entry in observed)
            {
                var device = snapshot.Devices.SingleOrDefault(device => device.Uri == entry.MediaUri);
                if (device == null || !device.InsertedKnown) continue;
                var terminal = tasks.TryGetValue(entry.OperationId, out var task) && task.Terminal;
                var restored = entry.Reference == null && !_ownedOperations.Contains(entry.OperationId) && snapshot.ConfirmsEmpty;
                if (!device.Inserted && (entry.Phase == RemoteMediaPhase.Settled || terminal || restored))
                    await UpdateAsync(entry.MediaUri, entry.OperationId, entry.Action, RemoteMediaPhase.Cleared, cancellation).ConfigureAwait(false);
                else if (device.Inserted && entry.Action == RemoteMediaAction.Insert)
                    await ObserveSourceAsync(entry, device.Image, entry.Phase == RemoteMediaPhase.Settled || terminal && !task.Failed, cancellation).ConfigureAwait(false);
            }
            return WithSourceState(snapshot);
        }
        finally { _gate.Release(); }
    }
    private RedfishMediaSnapshot WithSourceState(RedfishMediaSnapshot snapshot)
    {
        var operations = Volatile.Read(ref _operations).ToDictionary(entry => entry.MediaUri, StringComparer.Ordinal);
        return snapshot with { Devices = snapshot.Devices.Select(device => {
            operations.TryGetValue(device.Uri, out var entry);
            return device with {
                HasManagedSource = entry?.Action == RemoteMediaAction.Insert,
                SourceVerification = entry?.Action == RemoteMediaAction.Insert ? entry.SourceVerification : RemoteMediaSourceVerification.Unknown,
                CanInsert = device.CanInsert && !device.Inserted && string.IsNullOrEmpty(device.Image) && entry == null,
                CanEject = device.CanEject && !(entry is { Phase: RemoteMediaPhase.Submitting or RemoteMediaPhase.Accepted, WriteComplete: false })
            };
        }).ToArray() };
    }
    private async Task<RemoteMediaOperation> ObserveSourceAsync(RemoteMediaOperation entry, string? source, bool completed,
        CancellationToken cancellation, bool inserted = true)
    {
        var observed = await _store.ObserveSourceAsync(entry.MediaUri, entry.OperationId, source, completed, cancellation, inserted).ConfigureAwait(false);
        Volatile.Write(ref _operations, _operations.Where(item => item.MediaUri != observed.MediaUri).Append(observed).ToArray());
        return observed;
    }
    public async Task<bool> InsertAsync(RedfishMediaClient client, string uri, string image, bool writeProtected,
        uint timeoutMs, CancellationToken cancellation = default)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellation, client.Cancellation);
        cancellation = lifetime.Token;
        await _gate.WaitAsync(cancellation).ConfigureAwait(false);
        try
        {
            using var budget = new OperationBudget(timeoutMs);
            using var registration = cancellation.Register(budget.Cancel);
            await RestoreCoreAsync(cancellation).ConfigureAwait(false);
            var previous = _operations.SingleOrDefault(item => item.MediaUri == uri);
            var entry = await UpdateAsync(uri, previous?.OperationId, RemoteMediaAction.Insert, RemoteMediaPhase.Submitting, cancellation, source: image).ConfigureAwait(false)
                ?? throw new InvalidDataException();
            var result = await SubmitAsync(entry, budget, cancellation,
                remaining => client.InsertAsync(uri, image, writeProtected, remaining, cancellation)).ConfigureAwait(false);
            await UpdateAsync(uri, entry.OperationId, entry.Action, RemoteMediaPhase.Accepted, cancellation, result.Reference).ConfigureAwait(false);
            _nextPoll[entry.OperationId] = RedfishTaskDelay.Due(result.RetryAfter, Environment.TickCount64, DateTimeOffset.UtcNow);
            var confirmed = false;
            if (!result.Pending)
            {
                await ObserveSourceAsync(entry, null, true, cancellation, inserted: false).ConfigureAwait(false);
                var snapshot = await client.ReadAsync(budget.RemainingMilliseconds(), cancellation).ConfigureAwait(false);
                var device = snapshot.Devices.SingleOrDefault(device => device.Uri == uri);
                if (device is { InsertedKnown: true, Inserted: true }) {
                    var observed = await ObserveSourceAsync(entry, device.Image, true, cancellation).ConfigureAwait(false);
                    confirmed = observed.Phase == RemoteMediaPhase.Settled;
                }
            }
            return confirmed;
        }
        finally { _gate.Release(); }
    }
    public async Task<bool> EjectAsync(RedfishMediaClient client, string uri, uint timeoutMs, CancellationToken cancellation = default)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellation, client.Cancellation);
        cancellation = lifetime.Token;
        await _gate.WaitAsync(cancellation).ConfigureAwait(false);
        try
        {
            using var budget = new OperationBudget(timeoutMs);
            using var registration = cancellation.Register(budget.Cancel);
            await RestoreCoreAsync(cancellation).ConfigureAwait(false);
            var previous = _operations.SingleOrDefault(item => item.MediaUri == uri);
            var entry = await UpdateAsync(uri, previous?.OperationId, RemoteMediaAction.Eject, RemoteMediaPhase.Submitting, cancellation).ConfigureAwait(false)
                ?? throw new InvalidDataException();
            var result = await SubmitAsync(entry, budget, cancellation,
                remaining => client.EjectWithResultAsync(uri, remaining, cancellation)).ConfigureAwait(false);
            await UpdateAsync(uri, entry.OperationId, entry.Action,
                result.Confirmed ? RemoteMediaPhase.Cleared : RemoteMediaPhase.Accepted, cancellation, result.Write.Reference).ConfigureAwait(false);
            if (!result.Confirmed) _nextPoll[entry.OperationId] = RedfishTaskDelay.Due(result.Write.RetryAfter, Environment.TickCount64, DateTimeOffset.UtcNow);
            return result.Confirmed;
        }
        finally { _gate.Release(); }
    }
    public async IAsyncEnumerable<RedfishMediaSnapshot> PollAsync(RedfishMediaClient client, uint timeoutMs,
        [EnumeratorCancellation] CancellationToken cancellation = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation, client.Cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        using var budget = new OperationBudget(30000);
        while (HasPendingOperations && !deadline.IsCancellationRequested)
        {
            RedfishMediaSnapshot snapshot;
            try { snapshot = await ReadAsync(client, Math.Min(timeoutMs, budget.RemainingMilliseconds()), deadline.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested) { yield break; }
            catch (BcException error) when (error.Status is Bc.Timeout or Bc.Cancelled) { yield break; }
            yield return snapshot;
            if (!HasPendingOperations) yield break;
            var now = Environment.TickCount64;
            var due = Volatile.Read(ref _operations).Where(item => item.Phase is RemoteMediaPhase.Submitting or RemoteMediaPhase.Accepted)
                .Select(item => item.Reference == null ? now + 2000 : _nextPoll.GetValueOrDefault(item.OperationId, now + 1000)).DefaultIfEmpty(long.MaxValue).Min();
            var delay = Math.Max(1000, due - now);
            uint remaining;
            try { remaining = budget.RemainingMilliseconds(); }
            catch (BcException) { yield break; }
            if (delay >= remaining) yield break;
            try { await Task.Delay(TimeSpan.FromMilliseconds(delay), deadline.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested) { yield break; }
        }
    }

}
