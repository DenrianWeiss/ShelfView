using BControl.Core.Media;
using BControl.Core.Native;
using BControl.Core.Redfish;

namespace BControl.Core.Kvm;

public sealed record ConsoleConnectionOptions(string Address, string? CaFile = null, uint CertPolicy = 0,
    uint MinimumTls = 12, HostTimeout? Timeout = null, Socks5Connection? Proxy = null,
    Func<uint, CancellationToken, Task<bool>>? ConfirmPrivate = null, ConsoleHttpConnection HttpConnection = ConsoleHttpConnection.Automatic,
    ConsoleProtocolChoice? Protocol = null, CancellationToken Cancellation = default);

public static class ConsoleService
{
    public static IReadOnlyList<ConsoleProtocolChoice> Choices(Exception error)
    {
        if (error is not ConsoleLayoutSelectionRequiredException) return [];
        var choices = new ConsoleClientChoice[16];
        Bc.Check(ConsoleClientNative.bc_console_client_choices(choices, (uint)choices.Length, out var count), "kvm.title");
        return choices.Take(checked((int)count)).Select(choice => new ConsoleProtocolChoice(choice.Id, choice.GetTitle(), choice.Profile)).ToArray();
    }

    public static async Task<IKvmSession> ConnectAsync(ConsoleConnectionOptions record, DeviceCredential credential) =>
        await NativeConsoleClient.ConnectAsync(record, credential).ConfigureAwait(false);

    public static async Task<ILocalMediaSession?> MountIndependentAsync(ConsoleConnectionOptions record, DeviceCredential credential, string path)
    {
        try { return await NativeConsoleClient.OpenMediaAsync(record, credential, path).ConfigureAwait(false); }
        catch (Exception error) when (error is BcException { Status: Bc.Unsupported } or ConsoleFailureException { Status: Bc.Unsupported }) { return null; }
    }
}
