using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace BControl.Integration.Tests;
public sealed class FixtureProcess : IDisposable
{
    public int Port { get; }
    public string? Extra { get; }

    private readonly Process _process;
    private FixtureProcess(Process process, int port, string? extra)
    {
        _process = process;
        Port = port;
        Extra = extra;
    }

    public static async Task<FixtureProcess> StartAsync(string script, params string[] arguments)
    {
        var python = Environment.GetEnvironmentVariable("BC_TEST_PYTHON") ?? (OperatingSystem.IsWindows() ? "python" : "python3");
        var path = Path.Combine(AppContext.BaseDirectory, "fixtures", script);
        var allArgs = string.Join(" ", new[] { $"\"{path}\"" }.Concat(arguments.Select(a => $"\"{a}\"")));
        var info = new ProcessStartInfo
        {
            FileName = python,
            Arguments = allArgs,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
        };
        var process = Process.Start(info) ?? throw new InvalidOperationException("无法启动夹具进程");
        try
        {
            var ready = await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(30));
            if (ready == null || !ready.StartsWith("READY ", StringComparison.Ordinal))
            {
                var error = await process.StandardError.ReadToEndAsync();
                throw new InvalidOperationException($"夹具未就绪: {ready} {error}");
            }

            var parts = ready.Split(' ');
            return new FixtureProcess(process, int.Parse(parts[1]), parts.Length > 2 ? parts[2] : null);
        }
        catch
        {
            TryKill(process);
            throw;
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
                process.Kill(true);
        }
        catch
        {
        }
    }

    public void Dispose()
    {
        try
        {
            _process.StandardInput.Close();
            _process.WaitForExit(3000);
            if (!_process.HasExited)
                TryKill(_process);
        }
        catch
        {
            TryKill(_process);
        }
        finally
        {
            _process.Dispose();
        }
    }
}

public sealed class LocalRfbServer : IDisposable
{
    private readonly Task _beforeFrame;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _task;
    public byte[] Received { get; private set; } = Array.Empty<byte>();
    public Task Completion => _task;
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public LocalRfbServer(Task? beforeFrame = null)
    {
        _beforeFrame = beforeFrame ?? Task.CompletedTask;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        _task = Task.Run(RunAsync);
    }

    private async Task RunAsync()
    {
        using var client = await _listener.AcceptTcpClientAsync(_cts.Token);
        var stream = client.GetStream();
        var received = new List<byte>();
        try
        {
            // RFB 3.8 None 安全 + 2x2 桌面 + 一个 Raw 帧。
            await stream.WriteAsync(System.Text.Encoding.ASCII.GetBytes("RFB 003.008\n"));
            await ReadExactlyAsync(stream, received, 12); // 客户端版本
            await stream.WriteAsync(new byte[] { 1, 1 }); // 仅 None
            await ReadExactlyAsync(stream, received, 1); // 选择 None
            await stream.WriteAsync(new byte[] { 0, 0, 0, 0 }); // SecurityResult OK
            await ReadExactlyAsync(stream, received, 1); // ClientInit
            var init = new List<byte>
            {
                0,
                2,
                0,
                2
            };
            init.AddRange(new byte[] { 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0 });
            init.AddRange(new byte[] { 0, 0, 0, 0 });
            await stream.WriteAsync(init.ToArray()); // ServerInit
            // FramebufferUpdate: x=0,y=0,w=2,h=2, Raw 编码 0, 4 像素 RGBA 数据。
            var update = new List<byte>
            {
                0,
                0,
                0,
                1,
                0,
                0,
                0,
                0,
                0,
                2,
                0,
                2,
                0,
                0,
                0,
                0
            };
            for (var i = 0; i < 16; i++)
                update.Add((byte)(i * 16));
            await _beforeFrame.WaitAsync(_cts.Token);
            await stream.WriteAsync(update.ToArray());
            // 读取客户端请求/输入一小段时间。
            var buffer = new byte[256];
            using var timeout = new CancellationTokenSource(1500);
            try
            {
                while (true)
                {
                    var read = await stream.ReadAsync(buffer, timeout.Token);
                    if (read <= 0)
                        break;
                    received.AddRange(buffer.AsSpan(0, read).ToArray());
                }
            }
            catch (OperationCanceledException)
            {
            }

            Received = received.ToArray();
        }
        catch (OperationCanceledException)
        {
            Received = received.ToArray();
        }
    }

    private static async Task ReadExactlyAsync(NetworkStream stream, List<byte> received, int count)
    {
        var buffer = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, count - offset));
            if (read <= 0)
                throw new EndOfStreamException();
            offset += read;
        }

        received.AddRange(buffer);
    }

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
        try
        {
            _task.Wait(3000);
        }
        catch
        {
        }
    }
}
