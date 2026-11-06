using BControl.Core.Transport;

namespace BControl.Core.Tests;

public sealed class ConsoleSocketShutdownTests
{
    [Fact]
    public async Task CloseCancelsBlockedSenderBeforeWaitingForItsGate()
    {
        using var socket = new Socket { BlockSend = true };
        using var gate = new SemaphoreSlim(1);
        using var stop = new CancellationTokenSource();
        await gate.WaitAsync();
        var sending = Task.Run(async () =>
        {
            try { await socket.SendAsync([1], stop.Token); }
            catch (OperationCanceledException) { }
            finally { gate.Release(); }
        });
        await socket.Sending.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var closing = ConsoleSocketShutdown.CloseAsync(socket, gate, stop, _ => Task.CompletedTask);
        await Task.WhenAll(sending, closing).WaitAsync(TimeSpan.FromSeconds(4));
        Assert.False(await closing);
        Assert.True(stop.IsCancellationRequested);
        Assert.False(socket.IsOpen);
        Assert.Equal(1, gate.CurrentCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CloseBoundsFinalProtocolWrite(bool blocked)
    {
        using var socket = new Socket { BlockSend = blocked };
        using var gate = new SemaphoreSlim(1);
        using var stop = new CancellationTokenSource();
        var released = await ConsoleSocketShutdown.CloseAsync(socket, gate, stop,
            token => socket.SendAsync([1], token)).WaitAsync(TimeSpan.FromSeconds(4));
        Assert.Equal(!blocked, released);
        Assert.False(socket.IsOpen);
        Assert.Equal(1, gate.CurrentCount);
    }

    private sealed class Socket : IConsoleSocket, IDisposable
    {
        public bool BlockSend;
        public TaskCompletionSource Sending { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool IsOpen { get; private set; } = true;
        public void Abort() => IsOpen = false;
        public void Dispose() => Abort();
        public async Task SendAsync(byte[] data, CancellationToken token)
        {
            Sending.TrySetResult();
            if (BlockSend) await Task.Delay(Timeout.Infinite, token);
        }
    }
}
