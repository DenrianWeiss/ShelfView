using System.Runtime.InteropServices;
using BControl.Core.Native;
using BControl.Core.Redfish;
namespace BControl.Core.Http;

internal sealed class NativeHttpSession : IAsyncDisposable
{
    internal delegate uint Submit(IntPtr endpoint, IntPtr authentication, BcRedfishCompletion callback, IntPtr user, out IntPtr request);
    internal sealed record Response(uint Status, byte[] Body);
    private readonly RedfishRuntime _runtime;
    private readonly SemaphoreSlim _gate = new(1);
    private IntPtr _endpoint, _authentication;
    private bool _disposed;
    private static readonly BcRedfishCompletion Completed = (_, _, user) =>
        ((TaskCompletionSource)GCHandle.FromIntPtr(user).Target!).TrySetResult();
    private NativeHttpSession(RedfishRuntime runtime, IntPtr endpoint) { _runtime = runtime; _endpoint = endpoint; }
    internal static async Task<NativeHttpSession> CreateAsync(string address, string? caFile, uint policy, uint tlsMin, Socks5Connection? proxy)
    {
        var runtime = RedfishRuntime.Create();
        try
        {
            using var origin = BcStringPinned.Pin(address);
            using var ca = BcStringPinned.Pin(caFile ?? "");
            using var identity = BcStringPinned.Pin("console-http");
            var options = new BcEndpointOptions { StructSize = (uint)Marshal.SizeOf<BcEndpointOptions>(),
                AbiVersion = Bc.AbiVersion, Origin = origin.Value, CaFile = ca.Value,
                DeviceId = identity.Value, EndpointId = identity.Value, CertPolicy = policy, TlsMin = tlsMin, Flags = 1 };
            var endpoint = await runtime.InvokeAsync(() => {
                Bc.Check(NativeConnections.CreateEndpoint(runtime.Context, ref options, proxy, out var handle), "core.createEndpoint");
                return handle;
            }).ConfigureAwait(false);
            return new(runtime, endpoint);
        }
        catch { await runtime.DisposeAsync().ConfigureAwait(false); throw; }
    }
    internal async Task<Response> ExchangeAsync(Submit submit, bool authenticate = false,
        Func<IntPtr, uint>? validate = null, CancellationToken cancellation = default)
    {
        await _gate.WaitAsync(cancellation).ConfigureAwait(false);
        var request = IntPtr.Zero;
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var state = GCHandle.Alloc(done);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (authenticate && _authentication != IntPtr.Zero) Bc.Check(Bc.Busy, "core.login");
            request = await _runtime.InvokeAsync(() => {
                cancellation.ThrowIfCancellationRequested();
                Bc.Check(submit(_endpoint, _authentication, Completed, GCHandle.ToIntPtr(state), out var handle), "core.login");
                if (authenticate) { HttpNative.bc_request_retain(handle); _authentication = handle; }
                return handle;
            }).ConfigureAwait(false);
            await using (cancellation.Register(() => _ = _runtime.InvokeAsync(() => HttpNative.bc_request_cancel(request))).ConfigureAwait(false))
                await done.Task.ConfigureAwait(false);
            cancellation.ThrowIfCancellationRequested();
            return await _runtime.InvokeAsync(() => {
                if (validate != null) Bc.Check(validate(request), "core.login");
                return CopyResponse(request);
            }).ConfigureAwait(false);
        }
        finally
        {
            try { if (request != IntPtr.Zero) await _runtime.InvokeAsync(() => { HttpNative.bc_request_release(request); return 0; }).ConfigureAwait(false); }
            finally { state.Free(); _gate.Release(); }
        }
    }
    private static unsafe Response CopyResponse(IntPtr request)
    {
        var pointer = HttpNative.bc_request_response(request);
        if (pointer == IntPtr.Zero) Bc.Check(Bc.ProtocolError, "core.login");
        var response = Marshal.PtrToStructure<BcResponse>(pointer);
        Bc.Check(response.Status, "core.login");
        var body = new byte[checked((int)response.Body.Length)];
        if (body.Length != 0) Marshal.Copy((IntPtr)response.Body.Data, body, 0, body.Length);
        return new(response.HttpStatus, body);
    }
    internal async Task<T> InspectAuthenticationAsync<T>(Func<IntPtr, T> inspect)
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try { ObjectDisposedException.ThrowIf(_disposed, this); return await _runtime.InvokeAsync(() => inspect(_authentication)).ConfigureAwait(false); }
        finally { _gate.Release(); }
    }
    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposed) return;
            _disposed = true;
            await _runtime.InvokeAsync(() => {
                HttpNative.bc_request_release(_authentication); _authentication = IntPtr.Zero;
                NativeMethods.bc_endpoint_release(_endpoint); _endpoint = IntPtr.Zero; return 0;
            }).ConfigureAwait(false);
            await _runtime.DisposeAsync().ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }
}
