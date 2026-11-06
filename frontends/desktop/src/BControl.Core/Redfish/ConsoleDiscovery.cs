using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using BControl.Core.Native;

namespace BControl.Core.Redfish;
public sealed partial class RedfishSession
{
    public async Task<FeatureDetection> DetectIndependentMediaAsync(uint timeoutMs = 5000, CancellationToken cancellation = default)
    {
        cancellation.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(_disposed, this);
        return await _runtime.InvokeAsync(() => {
            cancellation.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(_disposed || _loggedOut, this);
            var result = new FeatureDetection.Result { StructSize = (uint)Marshal.SizeOf<FeatureDetection.Result>() };
            Bc.Check(ConsoleClientNative.bc_console_client_detect_media(_runtime.Context, _endpoint, timeoutMs, ref result), "core.probeCapabilities");
            cancellation.ThrowIfCancellationRequested();
            return new FeatureDetection(result);
        }).ConfigureAwait(false);
    }

    private static readonly BcRedfishCompletion PublicProbeCompleted = (_, result, user) =>
    {
        var done = (TaskCompletionSource<(uint Status, uint Http)>)GCHandle.FromIntPtr(user).Target!;
        var value = Marshal.PtrToStructure<BcRedfishResult>(result);
        done.TrySetResult((value.Status, value.HttpStatus));
    };

    public static async Task ProbePublicAsync(string address, string? ca, uint policy, uint tlsMin = 12, Socks5Connection? proxy = null, uint timeoutMs = 5000)
    {
        await using var runtime = RedfishRuntime.Create();
        var endpoint = await CreateEndpointAsync(runtime, address, ca ?? "", policy, new DeviceCredential("", ""), tlsMin, proxy).ConfigureAwait(false);
        var done = new TaskCompletionSource<(uint Status, uint Http)>(TaskCreationOptions.RunContinuationsAsynchronously);
        var state = GCHandle.Alloc(done);
        IntPtr operation = IntPtr.Zero;
        try
        {
            await runtime.InvokeAsync(() =>
            {
                var options = Options(timeoutMs);
                Bc.Check(NativeMethods.bc_redfish_probe(endpoint, ref options, PublicProbeCompleted, GCHandle.ToIntPtr(state), out operation), "kvm.title");
                return 0;
            });
            var result = await done.Task.ConfigureAwait(false);
            if (result.Status != Bc.Ok)
                throw new DiscoveryFailure(result.Status, result.Http, 0);
        }
        finally
        {
            await runtime.InvokeAsync(() =>
            {
                if (operation != IntPtr.Zero)
                    NativeMethods.bc_redfish_release(operation);
                NativeMethods.bc_endpoint_release(endpoint);
                return 0;
            });
            state.Free();
        }
    }

}

public static class ManualConsoleNativeFacade
{
    public static bool CanSelect(uint status, uint http) => ConsoleClientNative.bc_console_entry_can_select_manually(status, http) != 0;
}
