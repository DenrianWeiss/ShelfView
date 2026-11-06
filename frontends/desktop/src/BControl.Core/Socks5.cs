using System.Runtime.InteropServices;
using System.Text;
using BControl.Core.Native;

namespace BControl.Core;

public sealed class Socks5Connection
{
    public string Host { get; }
    public ushort Port { get; }
    private readonly string _username, _password;

    public Socks5Connection(string host, ushort port = 1080, string username = "", string password = "")
    {
        if (string.IsNullOrEmpty(host) || host.Length > 253 || port == 0 ||
            host.Any(c => c <= 32 || c >= 127 || "/@?#[]".Contains(c)) ||
            username == null || password == null ||
            Encoding.UTF8.GetByteCount(username) > 255 || Encoding.UTF8.GetByteCount(password) > 255 ||
            username.Contains('\0') || password.Contains('\0') || (username.Length == 0) != (password.Length == 0))
            throw new BcException(Bc.InvalidArgument, Bc.StatusText(Bc.InvalidArgument));
        Host = host; Port = port; _username = username; _password = password;
    }

    internal NativeProxy Pin() => new(Host, Port, _username, _password);
}

internal sealed class NativeProxy : IDisposable
{
    private readonly BcStringPinned _host, _username, _password;
    internal BcSocks5Proxy Value;
    internal NativeProxy(string host, ushort port, string username, string password)
    {
        _host = BcStringPinned.Pin(host);
        _username = BcStringPinned.Pin(username);
        _password = BcStringPinned.Pin(password);
        Value = new BcSocks5Proxy { StructSize = (uint)Marshal.SizeOf<BcSocks5Proxy>(),
            Host = _host.Value, Port = port, Username = _username.Value, Password = _password.Value };
    }
    public void Dispose()
    {
        _host.Dispose(); _username.Dispose(); _password.Dispose();
        Value = default;
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcSocks5Proxy
{
    public uint StructSize;
    public BcString Host, Username, Password;
    public uint Port;
}
