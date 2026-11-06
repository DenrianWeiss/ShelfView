using Avalonia;
using Avalonia.Media;
using SkiaSharp;

namespace BControl.Desktop;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        try
        {
            return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (LinuxSystemFontException)
        {
            Console.Error.WriteLine("ShelfView could not load a system font. Check Fontconfig and install DejaVu Sans or Liberation Sans.");
            return 1;
        }
    }

    public static AppBuilder BuildAvaloniaApp()
    {
        var builder = AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .With(new X11PlatformOptions { WmClass = "ShelfView" })
            .LogToTrace();
        if (!OperatingSystem.IsLinux())
            return builder;

        var options = new FontManagerOptions();
        return builder.With(options)
            .AfterPlatformServicesSetup(_ => options.DefaultFamilyName = SelectLinuxSystemFont())
            .AfterSetup(app =>
            {
                var manager = FontManager.Current;
                var family = manager.DefaultFontFamily;
                if (!manager.TryGetGlyphTypeface(new Typeface(family), out _))
                    throw new LinuxSystemFontException();
                app.Instance!.Resources["ContentControlThemeFontFamily"] = family;
            });
    }

    private static string SelectLinuxSystemFont()
    {
        var fonts = SKFontManager.Default;
        using var preferred = fonts.MatchFamily("sans-serif", SKFontStyle.Normal);
        var candidates = new[] { preferred?.FamilyName, "DejaVu Sans", "Liberation Sans" };
        foreach (var family in candidates.Concat(fonts.GetFontFamilies()).Distinct(StringComparer.Ordinal))
        {
            if (string.IsNullOrWhiteSpace(family))
                continue;
            using var typeface = fonts.MatchFamily(family, SKFontStyle.Normal);
            if (typeface != null && typeface.GetGlyph('A') != 0)
                return family;
        }

        throw new LinuxSystemFontException();
    }

    private sealed class LinuxSystemFontException : Exception;
}
