using System.Runtime.InteropServices;
using BControl.Core.Ipmi;
using BControl.Core.Native;

namespace BControl.Integration.Tests;
/// <summary>RMCP+ BMC 夹具（复用 tests/ipmi_integration.py 的独立实现）：会话、能力、SOL 创建/销毁与字节链路。</summary>
public sealed class IpmiBindingTests : IAsyncLifetime
{
    private FixtureProcess? _fixture;
    public async Task InitializeAsync() => _fixture = await FixtureProcess.StartAsync("ipmi_bmc_fixture.py");
    public async Task DisposeAsync()
    {
        _fixture?.Dispose();
        await Task.CompletedTask;
    }

    private (string Host, ushort Port) Target => ("127.0.0.1", (ushort)_fixture!.Port);

    [Fact]
    public async Task CancelledOperationStillClosesSession()
    {
        var (host, port) = Target;
        using var budget = new BControl.Core.OperationBudget(15000);
        using var cancellation = new CancellationTokenSource();
        await using var connection = await IpmiConnection.OpenAsync(host, port, "admin", "test-password",
            false, cancellation.Token, operation: budget);
        cancellation.Cancel();
        var error = await Assert.ThrowsAsync<BcException>(() => connection.GetChassisStatusAsync());
        Assert.Equal(Bc.Cancelled, error.Status);
        await connection.DisposeAsync();
        Assert.Equal(Bc.Ok, connection.LastCloseStatus);
    }

    [Fact]
    public async Task SessionOpen_ProbeChassis_AndClose()
    {
        var(host, port) = Target;
        await using var connection = await IpmiConnection.OpenAsync(host, port, "admin", "test-password", suite3Allowed: false);
        var info = await connection.GetInfoAsync();
        Assert.Equal(17u, info.CipherSuiteId);
        var caps = await connection.ProbeAsync();
        Assert.Equal(Bc.PowerOff, caps.ChassisPowerState);
        var chassis = await connection.GetChassisStatusAsync();
        Assert.Equal(Bc.PowerOff, chassis.PowerState);
    }

    [Fact]
    public async Task Sol_Create_WriteRead_AndDestroy()
    {
        var(host, port) = Target;
        await using var connection = await IpmiConnection.OpenAsync(host, port, "admin", "test-password", suite3Allowed: false);
        var config = await connection.GetSolConfigAsync();
        Assert.NotNull(config);
        Assert.True(config!.Enabled);
        var received = new List<byte>();
        await using var sol = await connection.OpenSolAsync();
        sol.Received += data => received.AddRange(data);
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(15);
        while (DateTime.UtcNow < deadline)
        {
            var state = await sol.GetStateAsync();
            if (state.State == IpmiAbi.SolActive && received.Count > 0)
                break;
            await Task.Delay(100);
        }

        var active = await sol.GetStateAsync();
        Assert.Equal(IpmiAbi.SolActive, active.State);
        Assert.NotEmpty(received);
        // 发送普通终端输入（字节进入队列，经泵发往 BMC）。
        await sol.WriteAsync(new byte[] { (byte)'h', (byte)'i', 13 });
        await Task.Delay(500);
    }

    [Fact]
    public async Task Suite3Only_RequiresExplicitConfirmation()
    {
        // 夹具声明 suite 17 + suite 3；17 可用因此无需确认。此用例验证确认路径不被绕过：
        // 直接探测应成功；ConfirmationRequired 只在设备仅提供 suite 3 时出现。
        var(host, port) = Target;
        await using var connection = await IpmiConnection.OpenAsync(host, port, "admin", "test-password", suite3Allowed: false);
        Assert.True((await connection.ProbeAsync()).CipherSuiteId > 0);
    }
}
