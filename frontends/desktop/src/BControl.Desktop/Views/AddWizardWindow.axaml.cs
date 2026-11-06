using Avalonia.Controls;
using Avalonia.Interactivity;
using BControl.Desktop.ViewModels;

namespace BControl.Desktop.Views;
public partial class AddWizardWindow : Window
{
    public AddWizardWindow()
    {
        InitializeComponent();
        Closed += (_, _) => { ViewModel.CancelProbe(); ViewModel.Password = ""; ViewModel.ProxyPassword = ""; };
    }

    private AddWizardViewModel ViewModel => (AddWizardViewModel)DataContext!;

    private async void OnProbe(object? sender, RoutedEventArgs e) => await ViewModel.ProbeAsync();
    private async void OnConfirmSuite3(object? sender, RoutedEventArgs e) => await ViewModel.ConfirmSuite3AndProbeIpmiAsync();
    private async void OnSave(object? sender, RoutedEventArgs e) => await SaveAsync(false);
    private async void OnSaveUnverified(object? sender, RoutedEventArgs e) => await SaveAsync(true);
    private async Task SaveAsync(bool unverified)
    {
        try
        {
            var record = await ViewModel.SaveAsync(saveUnverified: unverified);
            if (record != null)
                Close(record);
        }
        catch (Exception ex)
        {
            ViewModel.FailureMessage = ex.Message;
        }
    }

    private void OnCancel(object? sender, RoutedEventArgs e)
    {
        ViewModel.CancelProbe();
        Close(null);
    }
}
