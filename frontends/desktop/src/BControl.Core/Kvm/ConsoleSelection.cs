using System.Runtime.InteropServices;
using BControl.Core.Localization;
using BControl.Core.Native;

namespace BControl.Core.Kvm;

public enum ConsoleHttpConnection : uint { Automatic, Html5, Legacy, Redfish }

public sealed record ConsoleProtocolChoice
{
    public uint Id { get; }
    public string Title { get; }
    internal BcServiceProfile Profile { get; }
    internal ConsoleProtocolChoice(uint id, string title, BcServiceProfile profile) => (Id, Title, Profile) = (id, title, profile);
    public override string ToString() => Title;
}

public sealed class ConsoleHttpSelectionRequiredException : Exception
{
    public ConsoleHttpSelectionRequiredException() : base(Loc.T("kvm.http.choose")) { }
}

public sealed class ConsoleLayoutSelectionRequiredException : Exception
{
    public ConsoleLayoutSelectionRequiredException() : base(Loc.T("kvm.protocol.chooseLayout")) { }
}

public sealed class ConsoleFailureException : Exception
{
    public uint Status { get; }
    public uint HttpStatus { get; }
    public uint Phase { get; }
    public uint Cause { get; }
    public bool IsCredentialFailure => Phase == 2 && Cause == 1;
    internal ConsoleFailureException(BcConsoleFailure failure) : base(Bc.StatusText(failure.Status)) =>
        (Status, HttpStatus, Phase, Cause) = (failure.Status, failure.HttpStatus, failure.Phase, failure.Cause);
}
