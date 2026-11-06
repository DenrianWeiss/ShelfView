using Avalonia.Controls;

namespace BControl.Desktop.Views;

public partial class MediaCloseDialog : Window
{
    public MediaCloseDialog() => InitializeComponent();

    public MediaCloseDialog(string message) : this()
    {
        Message.Text = message;
    }

    private void OnKeep(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        => Close(ViewModels.MediaCloseChoice.KeepMounted);

    private void OnEject(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        => Close(ViewModels.MediaCloseChoice.EjectAndClose);

    private void OnCancel(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        => Close(null);
}
