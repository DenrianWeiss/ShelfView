namespace BControl.Core.Input;

public static class KvmPaste
{
    public static uint[]? Plan(string text)
    {
        var normalized = text.Replace("\r\n", "\n").Replace('\r', '\n');
        if (normalized.Any(c => c != '\n' && c != '\t' && (c < ' ' || c > '~')))
            return null;
        return normalized.Select(c => c == '\n' ? 0xff0du : c == '\t' ? 0xff09u : c).ToArray();
    }
}
