using BControl.Core.Native;

namespace BControl.Core.Redfish;
public readonly record struct RedfishMediaWriteResult(uint Flags, byte[]? Reference = null, string RetryAfter = "")
{
    public bool Pending => (Flags & RedfishAbi.TaskPending) != 0;
}

public sealed record RedfishMediaSnapshot(IReadOnlyList<VirtualMediaDevice> Devices, bool Complete)
{
    public bool ConfirmsEmpty => Complete && Devices.Count > 0 && Devices.All(device => device.InsertedKnown && !device.Inserted);
}
public static class RedfishMediaDiscovery
{
    public static async Task<RedfishMediaSnapshot> ReadAsync(RedfishSession session, uint budgetMs = 30000, CancellationToken cancellation = default)
    {
        using var budget = new OperationBudget(budgetMs);
        using var registration = cancellation.Register(budget.Cancel);
        var devices = new Dictionary<string, VirtualMediaDevice>(StringComparer.Ordinal);
        var managers = await session.DiscoverManagersAsync(budget.RemainingMilliseconds(), cancellation).ConfigureAwait(false);
        var complete = managers.Count > 0;
        foreach (var manager in managers) {
            cancellation.ThrowIfCancellationRequested();
            try {
                var list = await session.DiscoverVirtualMediaCollectionAsync(manager, budget.RemainingMilliseconds(), cancellation).ConfigureAwait(false);
                complete &= list.Supported;
                foreach (var uri in list.Members) {
                    cancellation.ThrowIfCancellationRequested();
                    try { devices[uri] = await session.GetVirtualMediaAsync(uri, budget.RemainingMilliseconds(), cancellation).ConfigureAwait(false); }
                    catch (BcException error) {
                        complete = false;
                        if (error.Status is Bc.Timeout or Bc.Cancelled) return new(devices.Values.ToArray(), false);
                    }
                }
            }
            catch (BcException error) {
                complete = false;
                if (error.Status is Bc.Timeout or Bc.Cancelled) return new(devices.Values.ToArray(), false);
            }
        }
        cancellation.ThrowIfCancellationRequested();
        return new(devices.Values.ToArray(), complete);
    }
}
