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
        if (e.Source is TabControl { SelectedItem: TabItem { Tag: ManagementDataViewModel model } })
            await model.LoadAsync();
    }

    private void OnClose(object? sender, RoutedEventArgs e) => Close();
}
