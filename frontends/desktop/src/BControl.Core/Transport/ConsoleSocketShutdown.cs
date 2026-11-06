namespace BControl.Core.Transport;

internal static class ConsoleSocketShutdown
{
    internal static async Task<bool> CloseAsync(IConsoleSocket? socket, SemaphoreSlim gate,
        CancellationTokenSource stop, Func<CancellationToken, Task> release)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        var acquired = false;
        try
        {
            await gate.WaitAsync(timeout.Token).ConfigureAwait(false);
            acquired = true;
            if (socket?.IsOpen == true) await release(timeout.Token).ConfigureAwait(false);
            return true;
        }
        catch { return false; }
        finally
        {
            stop.Cancel();
            socket?.Abort();
            if (acquired) gate.Release();
        }
    }
}
