using System.Text.Json.Serialization;

namespace BControl.Core.Localization;

/// <summary>词表结构；唯一来源为 frontends/i18n/catalog.json，以嵌入资源加载。</summary>
public sealed class LocalizationCatalog
{
    [JsonPropertyName("version")] public int Version { get; init; }
    [JsonPropertyName("default")] public string Default { get; init; } = "zh-CN";
    [JsonPropertyName("languages")] public List<LanguageOption> Languages { get; init; } = new();
    [JsonPropertyName("messages")] public Dictionary<string, Dictionary<string, string>> Messages { get; init; } = new();
}

public sealed record LanguageOption(
    [property: JsonPropertyName("tag")] string Tag,
    [property: JsonPropertyName("name")] string Name);
