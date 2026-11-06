using System.Text.Json;
using System.Text.Json.Serialization;

namespace BControl.Core;

[JsonConverter(typeof(HostTimeoutJsonConverter))]
public sealed record HostTimeout
{
    public uint Seconds { get; }
    public uint Milliseconds => Seconds * 1000;
    public HostTimeout(uint seconds)
    {
        if (seconds is < 1 or > 3600) throw new ArgumentOutOfRangeException(nameof(seconds));
        Seconds = seconds;
    }
}

public sealed class HostTimeoutJsonConverter : JsonConverter<HostTimeout>
{
    public override HostTimeout Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.Number || !reader.TryGetUInt32(out var seconds) || seconds is < 1 or > 3600)
            throw new JsonException("Timeout must be 1...3600 seconds");
        return new HostTimeout(seconds);
    }
    public override void Write(Utf8JsonWriter writer, HostTimeout value, JsonSerializerOptions options) => writer.WriteNumberValue(value.Seconds);
}
