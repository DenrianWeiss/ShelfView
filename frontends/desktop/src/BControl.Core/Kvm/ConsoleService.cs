using BControl.Core.Media;
using BControl.Core.Native;
using BControl.Core.Redfish;

namespace BControl.Core.Kvm;

public enum ConsoleMode : uint { Html5 = 1, Java = 2 }

public sealed record ConsoleModeSettings(ConsoleMode Current, uint SupportedModes)
{
    public ConsoleMode? Alternative => Enum.GetValues<ConsoleMode>()
        .Where(mode => mode != Current && (SupportedModes & (1u << ((int)mode - 1))) != 0)
        .Select(mode => (ConsoleMode?)mode).FirstOrDefault();
    public static string Title(ConsoleMode mode) => mode == ConsoleMode.Html5 ? "HTML5" : "Java";
}

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
        catch (Exception error) when (error is BcException { Status: Bc.Unsupported } or
            ConsoleFailureException { Status: Bc.Unsupported, RecommendedMode: null }) { return null; }
    }

    public static Task<ConsoleModeSettings?> GetOrSetModeAsync(ConsoleConnectionOptions connection,
        DeviceCredential credential, ConsoleMode? expected = null, ConsoleMode? target = null) =>
        Task.Run<ConsoleModeSettings?>(() =>
        {
            using var address = BcStringPinned.Pin(connection.Address);
            using var username = BcStringPinned.Pin(credential.Username);
            using var password = BcStringPinned.Pin(credential.Password);
            using var ca = BcStringPinned.Pin(connection.CaFile);
            using var proxy = connection.Proxy?.Pin();
            ClientCancelled cancelled = _ => connection.Cancellation.IsCancellationRequested ? 1 : 0;
            var options = new ConsoleClientOptions {
                StructSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<ConsoleClientOptions>(),
                AbiVersion = Bc.AbiVersion, TimeoutMs = connection.Timeout?.Milliseconds ?? 15000,
                Address = address.Value, Username = username.Value, Password = password.Value, CaFile = ca.Value,
                CertPolicy = connection.CertPolicy, TlsMin = connection.MinimumTls,
                Cancelled = System.Runtime.InteropServices.Marshal.GetFunctionPointerForDelegate(cancelled)
            };
            unsafe {
                var nativeProxy = proxy?.Value ?? default;
                if (proxy != null) options.Proxy = (IntPtr)(&nativeProxy);
                var info = new ConsoleModeInfo { StructSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<ConsoleModeInfo>() };
                var status = ConsoleClientNative.bc_console_client_mode(ref options,
                    (uint)(expected ?? 0), (uint)(target ?? 0), ref info);
                GC.KeepAlive(cancelled);
                if (target == null && status == Bc.Unsupported) return null;
                Bc.Check(status, "manage.consoleMode.title");
                return new((ConsoleMode)info.Current, info.SupportedModes);
            }
        }, connection.Cancellation);
}
