using Avalonia.Controls;
using BControl.Core.Localization;
using Avalonia.Interactivity;
using BControl.Desktop.ViewModels;

namespace BControl.Desktop.Views;
public partial class OverviewView : UserControl
{
    public OverviewView() => InitializeComponent();
    private MainViewModel ViewModel => (MainViewModel)DataContext!;

    private async void OnOpenKvm(object? sender, RoutedEventArgs e) => await OpenAsync(sender, WorkspaceFeature.Kvm);
    private async void OnOpenSol(object? sender, RoutedEventArgs e) => await OpenAsync(sender, WorkspaceFeature.Sol);
    private async void OnOpenMedia(object? sender, RoutedEventArgs e) => await OpenAsync(sender, WorkspaceFeature.Media);
    private async Task OpenAsync(object? sender, WorkspaceFeature feature)
    {
        if (sender is Button { CommandParameter: ServerRowViewModel row })
        {
            if (await ViewModel.RequireCredentialAsync(row.Record) != null)
                await ViewModel.OpenWorkspaceAsync(row.Record, feature);
        }
    }

    private async void OnManage(object? sender, RoutedEventArgs e)
    {
        if (sender is not Button { CommandParameter: ServerRowViewModel row })
            return;
        if (TopLevel.GetTopLevel(this)is not Window owner)
            return;
        if (await ViewModel.RequireCredentialAsync(row.Record) == null)
            return;
        var viewModel = new ServerControlViewModel(row.Record, ViewModel.CredentialProviderFor(row.Record));
        await new ServerControlWindow(viewModel).ShowDialog(owner);
        if (viewModel.Changed)
            await ViewModel.RefreshAsync();
    }

    private async void OnProxy(object? sender, RoutedEventArgs e)
    {
        if (sender is not Button { CommandParameter: ServerRowViewModel row } || TopLevel.GetTopLevel(this) is not Window owner)
            return;
        try
        {
            Services.StoredCredential? credential = null;
            if (row.Record.Proxy is { CredentialRef: { } reference } proxy && row.Record.ReadProxyCredential is { } read)
                credential = (await read(reference, proxy.Username, default)).Credential;
            await new ServerProxyWindow(ViewModel, row.Record, credential).ShowDialog(owner);
        }
        catch (Exception ex) { ViewModel.StatusMessage = ex.Message; }
    }

    private async void OnDelete(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { CommandParameter: ServerRowViewModel row })
        {
            if (TopLevel.GetTopLevel(this)is not Window owner)
                return;
            if (!await ConfirmDialog.ShowAsync(owner, Loc.T(ViewModel.ServerHasLocalMedia(row.ServerId) ? "server.deleteActiveMedia" : "server.deleteTitle")))
                return;
            if (!await ViewModel.EjectLocalMediaAsync(row.ServerId))
                return;
            try
            {
                await ViewModel.DeleteServerAsync(row);
            }
            catch (Exception ex)
            {
                ViewModel.StatusMessage = ex.Message;
            }
        }
    }
}
