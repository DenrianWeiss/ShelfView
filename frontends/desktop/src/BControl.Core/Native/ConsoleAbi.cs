using System.Runtime.InteropServices;

namespace BControl.Core.Native;

[StructLayout(LayoutKind.Sequential)]
internal struct BcServiceProfile
{
    public uint StructSize;
    public uint Service;
    public uint Family;
    public uint Variant;
    public uint Evidence;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcConsoleFailure
{
    public uint StructSize;
    public uint Status;
    public uint Phase;
    public uint Cause;
    public uint Profile;
    public uint HttpStatus;
    public int DeviceCode;
    public uint Service;
    public uint Family;
}

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate ulong BcClock(IntPtr user);

[StructLayout(LayoutKind.Sequential)]
internal struct BcRecoveryView
{
    public uint StructSize, State, Attempt;
    public BcServiceProfile Profile;
    public uint BudgetSize, TicketRefreshes, ProfileFallbacks;
}

internal static class RecoveryNative
{
    [DllImport("bcontrol", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_recovery_op_create(ref BcServiceProfile profile, ulong now, uint timeout, out IntPtr op);
    [DllImport("bcontrol", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bc_console_recovery_op_view_get(IntPtr op);
    [DllImport("bcontrol", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_recovery_op_succeeded(IntPtr op, uint attempt, ulong now);
    [DllImport("bcontrol", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_recovery_op_disconnected(IntPtr op, uint attempt, ref BcConsoleFailure failure, int authenticated, IntPtr alternate, int mediaActive, ulong now, uint timeout, out uint action);
    [DllImport("bcontrol", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_recovery_op_failed(IntPtr op, uint attempt, ref BcConsoleFailure failure, int authenticated, IntPtr alternate, int mediaActive, ulong now, out uint action);
    [DllImport("bcontrol", CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bc_console_recovery_op_resume(IntPtr op, uint attempt, int cleanup, ulong now, out BcServiceProfile profile);
    [DllImport("bcontrol", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bc_console_recovery_op_destroy(IntPtr op);
}

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint BcConsoleSend(IntPtr user, IntPtr data, uint length);
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate uint BcConsoleReceive(IntPtr user, IntPtr data, uint capacity, out uint received, uint timeout);
