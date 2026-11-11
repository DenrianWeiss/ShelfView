namespace BControl.Desktop.Services;

public static class DeviceAddress
{
    public static bool SameHost(string left, string right) =>
        Uri.TryCreate(left, UriKind.Absolute, out var a) && Uri.TryCreate(right, UriKind.Absolute, out var b) &&
        string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase);

    public static string ForProtocol(string address, uint protocol)
    {
        var value = address.Trim();
        if (!value.Contains("://") || !Uri.TryCreate(value, UriKind.Absolute, out var uri))
            return protocol == 1 && !value.Contains("://") ? "https://" + value : value;
        var host = uri.Host.Trim('[', ']');
        if (host.Contains(':')) host = "[" + host + "]";
        if (protocol == 2 && uri.Scheme is "https" or "http") return "ipmi://" + host;
        if (protocol != 2 && uri.Scheme == "ipmi") return "https://" + host;
        return value;
    }
}
