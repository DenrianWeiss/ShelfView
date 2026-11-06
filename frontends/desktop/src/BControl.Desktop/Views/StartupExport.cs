using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Platform.Storage;
using BControl.Core.Diagnostics;
using BControl.Core.Localization;
using BControl.Desktop.ViewModels;
using BControl.Desktop.Services;

namespace BControl.Desktop.Views;
public static class StartupExport
{
    public static async Task ShowAsync(Window owner, string origin)
    {
        try
        {
            await ExportAsync(owner, origin);
        }
        catch (Exception ex)
        {
            if (owner.DataContext is MainViewModel model)
                model.StatusMessage = ex.Message;
        }
    }

    private static async Task ExportAsync(Window owner, string origin)
    {
        var dialog = new Window
        {
            Title = Loc.T("diagnostics.export"),
            Width = 440,
            SizeToContent = SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner
        };
        var binary = new CheckBox
        {
            Content = Loc.T("diagnostics.binary"),
            IsChecked = false
        };
        var save = new Button
        {
            Content = Loc.T("diagnostics.save")
        };
        var cancel = new Button
        {
            Content = Loc.T("common.cancel")
        };
        save.Click += (_, _) => dialog.Close((bool? )(binary.IsChecked == true));
        cancel.Click += (_, _) => dialog.Close((bool? )null);
        dialog.Content = new StackPanel
        {
            Margin = new Thickness(20),
            Spacing = 12,
            Children =
            {
                binary,
                new TextBlock
                {
                    Text = Loc.T("diagnostics.contents"),
                    TextWrapping = Avalonia.Media.TextWrapping.Wrap
                },
                new StackPanel
                {
                    Orientation = Orientation.Horizontal,
                    Spacing = 8,
                    HorizontalAlignment = HorizontalAlignment.Right,
                    Children =
                    {
                        cancel,
                        save
                    }
                }
            }
        };
        var include = await dialog.ShowDialog<bool?>(owner);
        if (include == null)
            return;
        var file = await owner.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions { Title = Loc.T("diagnostics.export"), SuggestedFileName = "bcontrol-adaptation.zip", FileTypeChoices = new[] { new FilePickerFileType("ZIP") { Patterns = new[] { "*.zip" } } } });
        if (file == null)
            return;
        using (file)
        {
            await using var stream = await file.OpenWriteAsync();
            stream.SetLength(0);
            await StartupAssets.WriteZipAsync(stream, origin, include.Value);
        }
    }
}
