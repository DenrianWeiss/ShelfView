using System.Runtime.InteropServices;
using BControl.Core.Native;

namespace BControl.Core.Redfish;

public sealed partial class RedfishSession
{
    public readonly record struct NetworkRow(uint Flags, string Label, string Value, string Suffix)
    {
        public bool IsHeading => (Flags & 1) != 0;
        public bool LabelIsKey => (Flags & 2) != 0;
        public bool ValueIsKey => (Flags & 4) != 0;
    }

    public async Task<IReadOnlyList<NetworkRow>> GetNetworkRowsAsync(string uri, bool ethernet, uint timeoutMs, CancellationToken cancellation)
    {
        using var pinned = BcStringPinned.Pin(uri);
        return await RunAsync((BcRedfishCompletion completion, IntPtr userdata, out IntPtr operation) =>
        {
            var options = Options(timeoutMs);
            return ethernet
                ? NativeMethods.bc_redfish_get_ethernet_interface(_endpoint, pinned.Value, ref options, completion, userdata, out operation)
                : NativeMethods.bc_redfish_get_network_protocol(_endpoint, pinned.Value, ref options, completion, userdata, out operation);
        }, (op, res) =>
        {
            var response = SnapshotResult(op, res);
            if (response.Status != Bc.Ok)
                throw new BcException(response.Status, Bc.StatusText(response.Status), response.HttpStatus);
            var rows = new List<NetworkRow>();
            BcRedfishNetworkRowCallback callback = (pointer, _) =>
            {
                var row = Marshal.PtrToStructure<BcRedfishNetworkRow>(pointer);
                rows.Add(new(row.Flags, Text(row.Label), Text(row.Value), Text(row.Suffix)));
            };
            Bc.Check(NativeMethods.bc_redfish_network_rows(op, callback, IntPtr.Zero), "core.readSystem");
            GC.KeepAlive(callback);
            return (IReadOnlyList<NetworkRow>)rows;
        }, static op => NativeMethods.bc_redfish_cancel(op), cancellation, "core.readSystem").ConfigureAwait(false);
    }
}
