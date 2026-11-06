using BControl.Core.Kvm;
using BControl.Core.Media;

namespace BControl.Desktop.Services;
public static class ConsoleConnectionFactory
{
    public static string Address(ServerRecord record)
    {
        if (record.Address.StartsWith("ipmi://", StringComparison.OrdinalIgnoreCase))
            return new UriBuilder("https", new Uri(record.Address).Host).Uri.AbsoluteUri;
        return record.Address.Contains("://", StringComparison.Ordinal) ? record.Address : "https://" + record.Address;
    }

    private static async Task<ConsoleConnectionOptions> OptionsAsync(ServerRecord record, CancellationToken cancellation) =>
        new(Address(record), record.CaFile, record.CertPolicy, record.MinimumTls, record.Timeout,
            await record.ResolveProxyAsync(cancellation), record.ConfirmPrivate, record.ConsoleHttpConnection, record.ConsoleProtocol, cancellation);

    public static async Task<IKvmSession> ConnectAsync(ServerRecord record, StoredCredential credential, CancellationToken cancellation = default)
    {
        if (record.Capabilities.GraphicalConsole == false)
            throw new NotSupportedException(Core.Localization.Loc.T("media.localUnsupported"));
        return await ConsoleService.ConnectAsync(await OptionsAsync(record, cancellation), new(credential.Username, credential.Password));
    }

    public static async Task<ILocalMediaSession?> MountIndependentAsync(ServerRecord record, StoredCredential credential, string path, CancellationToken cancellation = default)
    {
        return await ConsoleService.MountIndependentAsync(await OptionsAsync(record, cancellation), new(credential.Username, credential.Password), path);
    }
}
