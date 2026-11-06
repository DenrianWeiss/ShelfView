using Avalonia.Controls;
using Avalonia.Interactivity;
using BControl.Desktop.ViewModels;

namespace BControl.Desktop.Views;

public partial class KvmPowerWindow : Window
{
    public KvmPowerWindow() => InitializeComponent();

    public KvmPowerWindow(ServerControlViewModel model) : this()
    {
        DataContext = model;
        Opened += async (_, _) => await model.LoadAsync();
    }

    private async void OnPower(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not ServerControlViewModel model ||
            sender is not Button { DataContext: ServerControlViewModel.PowerOption option })
            return;

        model.SelectedPower = option;
        await model.ApplyPowerAsync(ConfirmAsync);
    }

    private async void OnBoot(object? sender, RoutedEventArgs e)
    {
        if (DataContext is ServerControlViewModel model)
            await model.ApplyBootAsync(ConfirmAsync);
    }

    private Task<bool> ConfirmAsync(string message) => ConfirmDialog.ShowAsync(this, message);
    private void OnClose(object? sender, RoutedEventArgs e) => Close();
}
