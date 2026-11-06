using BControl.Core.Kvm;

namespace BControl.Integration.Tests;
/// <summary>本地 RFB 夹具：KVM 传输连接、握手、帧接收、键鼠字节与清理。</summary>
public sealed class KvmBindingTests
{
    [Fact]
    public async Task InputReachesTransportWhileFrameConsumerIsBlocked()
    {
        var publish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var release = new ManualResetEventSlim();
        using var server = new LocalRfbServer(publish.Task);
        await using var session = await KvmSession.ConnectAsync($"tcp://127.0.0.1:{server.Port}",
            null, null, null, 0, 5000, CancellationToken.None);
        session.FrameReceived += _ => { entered.TrySetResult(); release.Wait(); };
        try
        {
            publish.SetResult();
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await using var input = new KvmInputStream(session);
            await input.SendAsync(new KvmInputEvent.Chord(new uint[] { 'a' })).WaitAsync(TimeSpan.FromSeconds(1));
            await input.SendAsync(new KvmInputEvent.Pointer(2, 1, 1)).WaitAsync(TimeSpan.FromSeconds(1));
            await server.Completion.WaitAsync(TimeSpan.FromSeconds(5));
            var bytes = server.Received;
            Assert.Contains(Enumerable.Range(0, Math.Max(0, bytes.Length - 15)), offset =>
                bytes.AsSpan(offset, 16).SequenceEqual(new byte[] { 4, 1, 0, 0, 0, 0, 0, 97, 4, 0, 0, 0, 0, 0, 0, 97 }));
            Assert.Contains(Enumerable.Range(0, Math.Max(0, bytes.Length - 5)), offset =>
                bytes.AsSpan(offset, 6).SequenceEqual(new byte[] { 5, 4, 0, 1, 0, 1 }));
        }
        finally { release.Set(); }
    }

    [Fact]
    public async Task Connect_ReceivesFrame_SendsInput_AndCleansUp()
    {
        using var server = new LocalRfbServer();
        KvmFrame? frame = null;
        await using var session = await KvmSession.ConnectAsync($"tcp://127.0.0.1:{server.Port}", null, null, null, certPolicy: 0, timeoutMs: 5000, CancellationToken.None);
        var tcs = new TaskCompletionSource<KvmFrame>(TaskCreationOptions.RunContinuationsAsynchronously);
        session.FrameReceived += f => tcs.TrySetResult(f);
        if (session.LatestFrame is { } latest)
            tcs.TrySetResult(latest);
        var completed = await Task.WhenAny(tcs.Task, Task.Delay(8000));
        Assert.True(completed == tcs.Task, "未收到 KVM 帧");
        frame = await tcs.Task;
        Assert.Equal(2u, frame.Width);
        Assert.Equal(2u, frame.Height);
        Assert.Equal(2u * frame.Stride, (uint)frame.PixelsRgba.Length);
        await session.SendKeyAsync(1, 'a');
        await session.SendKeyAsync(0, 'a');
        await session.SendPointerAsync(1, 1, 1);
        await session.SendPointerAsync(0, 1, 1);
        await Task.Delay(1200);
        await session.DisposeAsync();
        await server.Completion.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.NotEmpty(server.Received);
        // 客户端输出应包含 SetPixelFormat/SetEncodings 请求和键鼠事件（由夹具累计）。
        Assert.Contains(Enumerable.Range(0, Math.Max(0, server.Received.Length - 7)), offset => server.Received.AsSpan(offset, 8).SequenceEqual(new byte[] { 4, 1, 0, 0, 0, 0, 0, (byte)'a' }));
    }
}
