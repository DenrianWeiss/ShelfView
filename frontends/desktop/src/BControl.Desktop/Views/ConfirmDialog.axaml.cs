using Avalonia.Controls;
using Avalonia.Interactivity;

namespace BControl.Desktop.Views;

public partial class ConfirmDialog : Window
{
    public ConfirmDialog() => InitializeComponent();

    public ConfirmDialog(string message) : this() => Message.Text = message;

    public static async Task<bool> ShowAsync(Window owner, string message, CancellationToken cancellation = default)
    {
        cancellation.ThrowIfCancellationRequested();
        var dialog = new ConfirmDialog(message);
        var pending = dialog.ShowDialog<bool>(owner);
        using var registration = cancellation.Register(() => Avalonia.Threading.Dispatcher.UIThread.Post(() => dialog.Close(false)));
        return await pending && !cancellation.IsCancellationRequested;
    }

    private void OnConfirm(object? sender, RoutedEventArgs e) => Close(true);

    private void OnCancel(object? sender, RoutedEventArgs e) => Close(false);
}
