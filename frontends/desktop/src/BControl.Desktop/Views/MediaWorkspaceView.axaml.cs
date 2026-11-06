using BControl.Core.Localization;
using Avalonia.Controls;
using Avalonia.Platform.Storage;
using Avalonia.Interactivity;
using BControl.Desktop.ViewModels;

namespace BControl.Desktop.Views;
public partial class MediaWorkspaceView : UserControl
{
    private async void OnExport(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is MediaWorkspaceViewModel vm && Avalonia.Controls.TopLevel.GetTopLevel(this)is Avalonia.Controls.Window window)
            await StartupExport.ShowAsync(window, BControl.Desktop.Services.ConsoleConnectionFactory.Address(vm.Record));
    }

    private MediaWorkspaceViewModel? _viewModel;
    public MediaWorkspaceView()
    {
        InitializeComponent();
        var monitor = new Avalonia.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        monitor.Tick += (_, _) => _viewModel?.RefreshLocal();
        AttachedToVisualTree += (_, _) => monitor.Start();
        DetachedFromVisualTree += (_, _) => monitor.Stop();
        DataContextChanged += (_, _) => _viewModel = DataContext as MediaWorkspaceViewModel;
    }

    private async void OnChooseIso(object? sender, RoutedEventArgs e)
    {
        if (_viewModel == null || TopLevel.GetTopLevel(this)is not { } top)
            return;
        var files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = Loc.T("media.chooseFile"), AllowMultiple = false, FileTypeFilter = new[] { new FilePickerFileType("ISO") { Patterns = new[] { "*.iso" } } }, });
        if (files.Count > 0)
            _viewModel.LocalPath = files[0].TryGetLocalPath() ?? "";
        foreach (var file in files)
            file.Dispose();
    }

    private async void OnMountLocal(object? sender, RoutedEventArgs e)
    {
        if (_viewModel != null)
            await _viewModel.MountLocalAsync();
    }

    private async void OnConsoleMode(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is { } model && TopLevel.GetTopLevel(this) is Window owner)
            await new ServerControlWindow(model.ConsoleModeManagement()).ShowDialog(owner);
    }

    private async void OnEjectLocal(object? sender, RoutedEventArgs e)
    {
        if (_viewModel != null)
            await _viewModel.EjectLocalAsync();
    }

    private async void OnConfirmCleanup(object? sender, RoutedEventArgs e)
    {
        if (_viewModel != null && TopLevel.GetTopLevel(this)is Window owner && await ConfirmDialog.ShowAsync(owner, Loc.T("media.acknowledgeRemovalConfirm")))
            await _viewModel.ConfirmLocalCleanupAsync();
    }

    private async void OnConnect(object? sender, RoutedEventArgs e)
    {
        if (_viewModel != null)
            await _viewModel.ConnectAsync();
    }

    private async void OnReload(object? sender, RoutedEventArgs e)
    {
        if (_viewModel != null)
            await _viewModel.ReloadAsync();
    }

    private async void OnMount(object? sender, RoutedEventArgs e)
    {
        if (_viewModel == null || sender is not Button { Tag: MediaDeviceRowViewModel row })
            return;
        var url = row.ImageUrl;
        if (string.IsNullOrWhiteSpace(url))
        {
            _viewModel.Status = Loc.T("media.enterImageUrl");
            return;
        }

        await _viewModel.MountAsync(row.Device, url.Trim(), writeProtected: true);
    }

    private async void OnEject(object? sender, RoutedEventArgs e)
    {
        if (_viewModel == null || sender is not Button { Tag: MediaDeviceRowViewModel row })
            return;
        await _viewModel.EjectAsync(row.Device);
    }


}
