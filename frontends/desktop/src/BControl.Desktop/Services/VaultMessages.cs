using BControl.Core.Localization;
using BControl.Core.Native;
using BControl.Core.Storage;

namespace BControl.Desktop.Services;
internal static class VaultMessages
{
    public static string Describe(Exception error) => error switch {
        VaultConflictException => Loc.T("vault.conflictSaved"),
        VaultConflictFullException => Loc.T("vault.conflictFull"),
        VaultChangedException => Loc.T("vault.changed"),
        BcException { Status: Bc.AuthenticationFailed } => Loc.T("vault.unlockFailed"),
        DllNotFoundException or EntryPointNotFoundException => Loc.T("vault.unavailable"),
        UnauthorizedAccessException or IOException => Loc.T("vault.fileUnavailable"),
        _ => Loc.T("vault.invalid")
    };
}
