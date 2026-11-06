using BControl.Core.Ipmi;
using BControl.Core.Native;
using BControl.Desktop.ViewModels;
using BControl.Core.Redfish;

namespace BControl.Desktop.Services;
/// <summary>首页管理操作：每次操作独立登录、执行并注销，不长期占用设备会话。</summary>
public interface IServerControlService
{
    Task<DiscoveryService.ControlSnapshot> ReadAsync(ServerRecord record, DeviceCredential credential, CancellationToken cancellation);
    Task<uint> PowerAsync(ServerRecord record, DeviceCredential credential, uint action, CancellationToken cancellation);
    Task<RedfishSession.BootApplyResult?> SetBootOnceAsync(ServerRecord record, DeviceCredential credential, uint target, uint mode, CancellationToken cancellation);
}

public sealed class RedfishServerControlService : IServerControlService
{
    public async Task<DiscoveryService.ControlSnapshot> ReadAsync(ServerRecord record, DeviceCredential credential, CancellationToken cancellation) => await DiscoveryService.ReadControlsAsync(record.Address, credential, record.SystemUri, record.CaFile ?? "", record.CertPolicy, cancellation, tlsMin: record.MinimumTls, proxy: await record.ResolveProxyAsync(cancellation), timeout: record.Timeout);
    public async Task<uint> PowerAsync(ServerRecord record, DeviceCredential credential, uint action, CancellationToken cancellation) => await DiscoveryService.PowerAsync(record.Address, credential, record.SystemUri, action, record.CaFile ?? "", record.CertPolicy, cancellation, tlsMin: record.MinimumTls, proxy: await record.ResolveProxyAsync(cancellation), timeout: record.Timeout);
    public async Task<RedfishSession.BootApplyResult?> SetBootOnceAsync(ServerRecord record, DeviceCredential credential, uint target, uint mode, CancellationToken cancellation) => await DiscoveryService.SetBootOnceAsync(record.Address, credential, record.SystemUri, target, mode, record.CaFile ?? "", record.CertPolicy, cancellation, tlsMin: record.MinimumTls, proxy: await record.ResolveProxyAsync(cancellation), timeout: record.Timeout);
}

public sealed class IpmiServerControlService : IServerControlService
{
    private static async Task<IpmiConnection> OpenAsync(ServerRecord record, DeviceCredential credential, CancellationToken cancellation, Core.OperationBudget? operation = null)
    {
        var(host, port) = SolWorkspaceViewModel.ParseAddress(record.Address, record.Protocol);
        return await IpmiConnection.OpenAsync(host, port, credential.Username, credential.Password, record.Suite3Confirmed, cancellation, await record.ResolveProxyAsync(cancellation), record.Timeout, operation);
    }

    public async Task<DiscoveryService.ControlSnapshot> ReadAsync(ServerRecord record, DeviceCredential credential, CancellationToken cancellation)
    {
        using var operation = new Core.OperationBudget(record.Timeout?.Milliseconds ?? 15000);
        await using var connection = await OpenAsync(record, credential, cancellation, operation);
        await connection.GetChassisStatusAsync();
        return new(new(await connection.GetPowerActionsAsync(), ""), await connection.GetBootAsync(), 0);
    }

    public async Task<uint> PowerAsync(ServerRecord record, DeviceCredential credential, uint action, CancellationToken cancellation)
    {
        using var operation = new Core.OperationBudget(record.Timeout?.Milliseconds ?? 15000);
        await using var connection = await OpenAsync(record, credential, cancellation, operation);
        await connection.PowerAsync(action);
        return 0;
    }

    public async Task<RedfishSession.BootApplyResult?> SetBootOnceAsync(ServerRecord record, DeviceCredential credential, uint target, uint mode, CancellationToken cancellation)
    {
        using var operation = new Core.OperationBudget(record.Timeout?.Milliseconds ?? 15000);
        await using var connection = await OpenAsync(record, credential, cancellation, operation);
        return await connection.SetBootOnceAsync(target, mode);
    }
}
