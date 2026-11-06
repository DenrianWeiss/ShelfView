using Avalonia.Controls;
using Avalonia.Interactivity;
using BControl.Desktop.ViewModels;

namespace BControl.Desktop.Views;
public partial class ServerControlWindow : Window
{
    private readonly ServerControlViewModel? _viewModel;
    public ServerControlWindow() => InitializeComponent();
    public ServerControlWindow(ServerControlViewModel viewModel) : this()
    {
        _viewModel = viewModel;
        DataContext = viewModel;
        Opened += async (_, _) =>
        {
            try
            {
                if (viewModel.FocusConsoleMode)
                {
                    Sections.SelectedItem = NetworkTab;
                    await Task.WhenAll(viewModel.Network.LoadAsync(), viewModel.LoadConsoleModeAsync());
                }
                await viewModel.LoadAsync();
            }
            catch (Exception ex)
            {
                viewModel.SetFailure(ex);
            }
        };
        Closed += (_, _) => viewModel.Dispose();
    }

    private async void OnBoot(object? sender, RoutedEventArgs e)
    {
        if (_viewModel == null)
            return;
        try
        {
            await _viewModel.ApplyBootAsync(message => ConfirmDialog.ShowAsync(this, message));
        }
        catch (Exception ex)
        {
            _viewModel.SetFailure(ex);
        }
    }

    private async void OnSectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (e.Source is not TabControl { SelectedItem: TabItem { Tag: ManagementDataViewModel model } item })
            return;
        if (item == NetworkTab && _viewModel is { } server)
            await Task.WhenAll(model.LoadAsync(), server.LoadConsoleModeAsync());
        else
            await model.LoadAsync();
    }

    private async void OnSwitchConsoleMode(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is { } model)
            await model.SwitchConsoleModeAsync(message => ConfirmDialog.ShowAsync(this, message));
    }

    private async void OnRefreshConsoleMode(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is { } model) await model.LoadConsoleModeAsync(refresh: true);
    }

    private void OnClose(object? sender, RoutedEventArgs e) => Close();
}
