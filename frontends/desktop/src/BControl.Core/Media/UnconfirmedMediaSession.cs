namespace BControl.Core.Media;
internal sealed class UnconfirmedMediaSession(string name, string error) : ILocalMediaSession
{
    public string Name => name;
    public bool IsActive => false;
    public bool RemovalUnconfirmed => true;
    public string? Error => error;

    public Task<bool> EjectAsync() => Task.FromResult(false);
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
