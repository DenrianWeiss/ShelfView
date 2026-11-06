using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using BControl.Core.Native;

namespace BControl.Core;

public sealed class OperationBudget : IDisposable
{
    private readonly object _gate = new();
    private readonly OperationHandle _handle;

    public OperationBudget(uint milliseconds)
    {
        Bc.Check(bc_operation_create((ulong)Environment.TickCount64, milliseconds, out _handle), "error.deviceTimeout");
    }

    public uint RemainingMilliseconds()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_handle.IsClosed, this);
            Bc.Check(bc_operation_remaining(_handle, (ulong)Environment.TickCount64, out var remaining), "error.deviceTimeout");
            return remaining;
        }
    }

    public void Cancel()
    {
        lock (_gate) { if (!_handle.IsClosed) bc_operation_cancel(_handle); }
    }

    public void Dispose() { lock (_gate) _handle.Dispose(); }

    private sealed class OperationHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public OperationHandle() : base(true) { }
        protected override bool ReleaseHandle() { bc_operation_destroy(handle); return true; }
    }

    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_operation_create(ulong now, uint timeout, out OperationHandle operation);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_operation_remaining(OperationHandle operation, ulong now, out uint remaining);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    private static extern void bc_operation_cancel(OperationHandle operation);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    private static extern void bc_operation_destroy(IntPtr operation);
}
