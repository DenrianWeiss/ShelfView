using System.Collections.Concurrent;
using BControl.Core.Kvm;

namespace BControl.Core.Tests;

public sealed class KvmStreamsTests
{
    [Fact]
    public async Task InputDoesNotWaitForVideoAndChordRemainsAtomic()
    {
        var drawing = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var video = new KvmVideoStream(async _ => { drawing.TrySetResult(); await release.Task; });
        var session = new FakeSession();
        await using var input = new KvmInputStream(session);
        try
        {
            video.Publish(new KvmFrame(1, 1, 4, "", new byte[4]));
            await drawing.Task.WaitAsync(TimeSpan.FromSeconds(2));
            var chord = input.SendAsync(new KvmInputEvent.Chord(new uint[] { 1, 2 }));
            var pointer = input.SendAsync(new KvmInputEvent.Pointer(1, 10, 20));
            await Task.WhenAll(chord, pointer).WaitAsync(TimeSpan.FromSeconds(2));
            Assert.Equal(new[] { "1:1", "1:2", "0:2", "0:1", "pointer:1:10:20" }, session.Input.ToArray());
        }
        finally { release.TrySetResult(); }
    }

    [Fact]
    public async Task BlockedDecoderDoesNotBlockInputAndPreservesDeltaOrder()
    {
        using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var decoded = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var frames = new ConcurrentQueue<int>();
        await using var decoder = new KvmDecodeStream<int>(frame =>
        {
            if (frame == 1) { entered.TrySetResult(); release.Wait(); }
            frames.Enqueue(frame);
            if (frame == 2) decoded.TrySetResult();
        });
        var session = new FakeSession();
        await using var input = new KvmInputStream(session);
        try
        {
            decoder.Submit(1, 4);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
            decoder.Submit(2, 4);
            await input.SendAsync(new KvmInputEvent.Key(1, 42)).WaitAsync(TimeSpan.FromSeconds(2));
            Assert.Equal(new[] { "1:42" }, session.Input.ToArray());
            Assert.Empty(frames);
        }
        finally { release.Set(); }
        await decoded.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(new[] { 1, 2 }, frames.ToArray());
    }

    [Fact]
    public async Task StoppingDecoderReleasesExecutedAndQueuedJobs()
    {
        using var unblock = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executed = new ConcurrentQueue<int>();
        var released = new ConcurrentQueue<int>();
        var decoder = new KvmDecodeStream<int>(job =>
        {
            executed.Enqueue(job);
            entered.TrySetResult();
            unblock.Wait();
        }, release: released.Enqueue);
        try
        {
            decoder.Submit(1, 4);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
            decoder.Submit(2, 4);
            var stopping = decoder.DisposeAsync().AsTask();
            unblock.Set();
            await stopping.WaitAsync(TimeSpan.FromSeconds(2));
            Assert.Equal(new[] { 1 }, executed.ToArray());
            Assert.Equal(new[] { 1, 2 }, released.ToArray());
        }
        finally { unblock.Set(); await decoder.DisposeAsync(); }
    }

    [Fact]
    public async Task ScrollReleasesWheelAndRfbAdapterPreservesButtons()
    {
        Assert.Equal((byte)4, KvmPointer.RfbButtons(2));
        Assert.Equal((byte)2, KvmPointer.RfbButtons(4));
        Assert.Equal((byte)15, KvmPointer.RfbButtons(15));
        var session = new FakeSession();
        await using var input = new KvmInputStream(session);
        await input.SendAsync(new KvmInputEvent.Scroll(2, 10, 20, 1));
        Assert.Equal(new[] { "pointer:10:10:20", "pointer:2:10:20" }, session.Input.ToArray());
    }

    [Fact]
    public async Task RfbScrollAttemptsReleaseAfterSendFailure()
    {
        var buttons = new List<byte>();
        await Assert.ThrowsAsync<IOException>(() => KvmPointer.RfbScrollAsync((value, _, _) =>
        {
            buttons.Add(value);
            return buttons.Count == 1 ? Task.FromException(new IOException("send failed")) : Task.CompletedTask;
        }, 2, 10, 20, -1));
        Assert.Equal(new byte[] { 18, 2 }, buttons);
    }

    private sealed class FakeSession : IKvmSession
    {
        public ConcurrentQueue<string> Input { get; } = new();
        public event Action<KvmFrame>? FrameReceived { add { } remove { } }
        public event Action<string>? Failed { add { } remove { } }
        public event Action? Closed { add { } remove { } }
        public KvmFrame? LatestFrame => null;
        public bool IsConnected => true;
        public Task SendKeyAsync(int down, uint keysym) { Input.Enqueue($"{down}:{keysym}"); return Task.CompletedTask; }
        public bool SupportsScroll => true;
        public Task SendScrollAsync(byte buttons, ushort x, ushort y, sbyte wheel) =>
            KvmPointer.RfbScrollAsync(SendPointerAsync, buttons, x, y, wheel);
        public Task SendPointerAsync(byte buttons, ushort x, ushort y) { Input.Enqueue($"pointer:{buttons}:{x}:{y}"); return Task.CompletedTask; }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
