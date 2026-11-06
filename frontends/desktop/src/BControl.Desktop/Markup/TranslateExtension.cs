using Avalonia.Data;
using Avalonia.Markup.Xaml;
using BControl.Core.Localization;

namespace BControl.Desktop.Markup;

/// <summary>XAML 用法：<c>Text="{loc:Tr common.cancel}"</c>。</summary>
public sealed class TrExtension : MarkupExtension
{
    public TrExtension() { }
    public TrExtension(string key) => Key = key;

    public string Key { get; set; } = "";

    public override object ProvideValue(IServiceProvider serviceProvider) =>
        new Binding { Path = $"[{Key}]", Source = Loc.Instance, Mode = BindingMode.OneWay };
}
