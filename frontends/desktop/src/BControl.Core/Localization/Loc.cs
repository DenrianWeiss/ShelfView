using System.ComponentModel;
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using BControl.Core.Native;

namespace BControl.Core.Localization;

/// <summary>
/// 进程级词表。XAML 通过 <c>{loc:Tr key}</c> 绑定到索引器；代码使用 <see cref="T"/>
/// 或 <see cref="F"/>。语言选择保存在用户配置目录，缺失时按系统语言回退。
/// </summary>
public sealed class Loc : INotifyPropertyChanged
{
    private const string ResourceName = "BControl.Core.i18n.catalog.json";
    private static readonly Regex Placeholder = new(@"\{([a-zA-Z0-9_]+)\}", RegexOptions.Compiled);
    private static readonly Loc Shared = new();

    private readonly LocalizationCatalog _catalog;
    private string _language;

    private Loc()
    {
        _catalog = LoadCatalog();
        _language = InitialLanguage();
    }

    public static Loc Instance => Shared;

    public event PropertyChangedEventHandler? PropertyChanged;
    public event Action? LanguageChanged;

    public IReadOnlyList<LanguageOption> Languages => _catalog.Languages;
    public string DefaultLanguage => _catalog.Default;

    public string Language
    {
        get => _language;
        set
        {
            if (string.Equals(_language, value, StringComparison.Ordinal) || !IsSupported(value)) return;
            _language = value;
            SavePreference(value);
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Language)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item"));
            LanguageChanged?.Invoke();
        }
    }

    public string this[string key] => Get(key);

    public bool IsSupported(string? language) =>
        !string.IsNullOrEmpty(language) && _catalog.Languages.Any(item => item.Tag == language);

    public string Get(string key, string? fallback = null)
    {
        if (_catalog.Messages.TryGetValue(key, out var message))
        {
            if (message.TryGetValue(_language, out var text) && !string.IsNullOrEmpty(text)) return text;
            if (message.TryGetValue(_catalog.Default, out var defaultText) && !string.IsNullOrEmpty(defaultText)) return defaultText;
        }
        return fallback ?? key;
    }

    public string Format(string key, params (string Name, object? Value)[] args)
    {
        var template = Get(key);
        return Placeholder.Replace(template, match =>
        {
            foreach (var (name, value) in args)
                if (name == match.Groups[1].Value)
                    return Convert.ToString(value, CultureInfo.CurrentCulture) ?? string.Empty;
            return match.Value;
        });
    }

    /// <summary>把 C 核心的稳定状态 token 映射为用户文案。</summary>
    public string Status(uint status)
    {
        var token = Bc.StatusString(status);
        return Get($"error.status.{token}", token);
    }

    public static string T(string key) => Shared.Get(key);
    public static string F(string key, params (string Name, object? Value)[] args) => Shared.Format(key, args);

    private static LocalizationCatalog LoadCatalog()
    {
        using var stream = typeof(Loc).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException($"Missing embedded resource {ResourceName}");
        return JsonSerializer.Deserialize<LocalizationCatalog>(stream, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
        }) ?? throw new InvalidOperationException($"Invalid embedded resource {ResourceName}");
    }

    private string InitialLanguage()
    {
        var saved = ReadPreference();
        if (IsSupported(saved)) return saved!;
        var system = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
        if (system.Equals("zh", StringComparison.OrdinalIgnoreCase) && IsSupported("zh-CN")) return "zh-CN";
        if (IsSupported("en")) return "en";
        return _catalog.Default;
    }

    private static string PreferencePath()
    {
        var root = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (string.IsNullOrEmpty(root)) root = Path.GetTempPath();
        return Path.Combine(root, "bControl", "language");
    }

    private static string? ReadPreference()
    {
        try
        {
            var path = PreferencePath();
            return File.Exists(path) ? File.ReadAllText(path).Trim() : null;
        }
        catch { return null; }
    }

    private static void SavePreference(string language)
    {
        try
        {
            var path = PreferencePath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, language);
        }
        catch { /* 语言选择只是偏好，不阻塞 UI */ }
    }
}
