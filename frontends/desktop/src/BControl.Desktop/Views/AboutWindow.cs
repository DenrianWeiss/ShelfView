using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using BControl.Core.Localization;

namespace BControl.Desktop.Views;

public sealed class AboutWindow : Window
{
    private static readonly (string Name, string License)[] Libraries =
    [
        ("Avalonia", "MIT"),
        ("Iciclecreek.Avalonia.Terminal", "MIT"),
        ("Porta.Pty", "MIT"),
        ("XTerm.NET", "MIT"),
        ("SkiaSharp.HarfBuzz", "MIT"),
        ("Unicode.net", "MIT"),
        ("Wcwidth", "MIT"),
        ("curl", "curl license"),
        ("OpenSSL", "Apache-2.0"),
        ("yyjson", "MIT"),
        ("yxml", "MIT")
    ];

    public AboutWindow()
    {
        Title = Loc.T("app.aboutMenu");
        Width = 440;
        Height = 520;
        MinWidth = 380;
        MinHeight = 420;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        var libraries = new StackPanel { Spacing = 5 };
        foreach (var (name, license) in Libraries)
            libraries.Children.Add(new TextBlock { Text = $"{name} — {license}" });

        var content = new StackPanel { Margin = new Thickness(24), Spacing = 14 };
        content.Children.Add(new TextBlock { Text = Loc.T("app.aboutTitle"), FontSize = 24, FontWeight = FontWeight.SemiBold });
        content.Children.Add(new TextBlock { Text = Loc.T("app.aboutDescription"), Foreground = Brushes.Gray });
        content.Children.Add(new HyperlinkButton { Content = "shelfview.permutation.work", NavigateUri = new Uri("https://shelfview.permutation.work") });
        content.Children.Add(new TextBlock { Text = Loc.T("app.aboutLibraries"), FontWeight = FontWeight.SemiBold, Margin = new Thickness(0, 8, 0, 0) });
        content.Children.Add(new ScrollViewer { Content = libraries, MaxHeight = 280 });
        var close = new Button { Content = Loc.T("app.aboutClose"), HorizontalAlignment = HorizontalAlignment.Right, MinWidth = 88 };
        close.Click += (_, _) => Close();
        content.Children.Add(close);
        Content = content;
    }
}
