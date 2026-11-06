using System.Runtime.InteropServices;
using BControl.Core.Native;

namespace BControl.Core.Ipmi;

internal sealed class IpmiIoGuard : IDisposable
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate ulong Clock(IntPtr user);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint Check(IntPtr user, out uint remaining);
    private readonly Clock _clock = _ => (ulong)Environment.TickCount64;
    private readonly Check _check;
    private OperationBudget? _budget;
    private CancellationToken _cancellation;
    private IntPtr _handle;
    public IntPtr Handle => _handle;
    public IntPtr Io => bc_ipmi_io_guard_get(_handle);

    // Configuration changes occur only while the session owner is idle.
    public IpmiIoGuard(IntPtr upstream, OperationBudget budget, CancellationToken cancellation)
    {
        _budget = budget; _cancellation = cancellation;
        _check = CheckBudget;
        Bc.Check(bc_ipmi_io_guard_create(upstream, _clock, _check, IntPtr.Zero, out _handle), "core.createSession");
    }
    public void Configure(OperationBudget? budget, CancellationToken cancellation)
    { _budget = budget; _cancellation = cancellation; }
    public void EnsureAvailable() => Bc.Check(CheckBudget(IntPtr.Zero, out _), "core.probeCapabilities");
    private uint CheckBudget(IntPtr user, out uint remaining)
    {
        remaining = 0;
        if (_cancellation.IsCancellationRequested) return Bc.Cancelled;
        try { remaining = _budget?.RemainingMilliseconds() ?? uint.MaxValue; return Bc.Ok; }
        catch (BcException error) { return error.Status; }
        catch { return Bc.IoError; }
    }
    public void Dispose()
    {
        bc_ipmi_io_guard_destroy(_handle); _handle = IntPtr.Zero;
        GC.KeepAlive(_clock); GC.KeepAlive(_check);
    }
    [DllImport(NativeLibs.Ipmi, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_ipmi_io_guard_create(IntPtr upstream, Clock clock, Check check, IntPtr user, out IntPtr guard);
    [DllImport(NativeLibs.Ipmi, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr bc_ipmi_io_guard_get(IntPtr guard);
    [DllImport(NativeLibs.Ipmi, CallingConvention = CallingConvention.Cdecl)]
    private static extern void bc_ipmi_io_guard_destroy(IntPtr guard);
}
