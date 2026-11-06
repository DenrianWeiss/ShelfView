using System.Runtime.InteropServices;
using BControl.Core.Native;

namespace BControl.Core.Kvm;
internal interface IConsoleProtocol
{
    BcServiceProfile Profile { get; }

    BcConsoleFailure Failure { get; }

    bool CleanupSucceeded { get; }
}

internal static class ConsoleProtocol
{
    public static BcConsoleFailure Capture(IntPtr session, Exception error, ref BcServiceProfile profile)
    {
        if (session != IntPtr.Zero)
        {
            var info = ConsoleNative.Info(session);
            if ((info.Flags & 8) != 0) profile = info.Profile;
            if ((info.Flags & 16) != 0 && info.Failure.Status != Bc.Ok) return info.Failure;
        }
        return Failure(IntPtr.Zero, error, profile);
    }
    public static BcConsoleFailure Failure(IntPtr pointer, Exception error, BcServiceProfile profile)
    {
        if (pointer != IntPtr.Zero)
        {
            var failure = Marshal.PtrToStructure<BcConsoleFailure>(pointer);
            if (failure.Status != Bc.Ok)
                return failure;
        }

        return new()
        {
            StructSize = (uint)Marshal.SizeOf<BcConsoleFailure>(),
            Status = error is BcException ex ? ex.Status : error is IOException ? Bc.IoError : Bc.ProtocolError,
            Phase = 4,
            Service = profile.Service,
            Family = profile.Family,
            Profile = profile.Variant
        };
    }
}

internal sealed record ConsoleAttempt(BcServiceProfile Profile, BcConsoleFailure Failure, bool Cleaned)
{
    internal static readonly object Key = new();
}
