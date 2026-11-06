namespace BControl.Desktop.Services;

// Local reads may outlive cancellation; keep one pending read per identity and
// let each caller stop waiting without starting a device operation afterward.
internal sealed class PendingReadCache<TKey, TValue> where TKey : notnull
{
    private readonly object _gate = new();
    private readonly Dictionary<TKey, Task<TValue>> _pending = new();
    public Task<TValue> ReadAsync(TKey key, Func<CancellationToken, Task<TValue>> read, CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        Task<TValue> task;
        lock (_gate)
        {
            if (!_pending.TryGetValue(key, out task!))
            {
                task = Task.Run(async () =>
                {
                    cancellation.ThrowIfCancellationRequested();
                    return await read(cancellation).ConfigureAwait(false);
                });
                _pending[key] = task;
                _ = task.ContinueWith(completed =>
                {
                    _ = completed.Exception;
                    lock (_gate)
                        if (_pending.TryGetValue(key, out var current) && ReferenceEquals(current, completed))
                            _pending.Remove(key);
                }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }
        return task.WaitAsync(cancellation);
    }
}
