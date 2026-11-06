using BControl.Core.Localization;
using BControl.Core.Inventory;
using BControl.Core.Diagnostics;
using BControl.Desktop.Services;
using Avalonia.Platform.Storage;
using Avalonia.Controls;
using Avalonia.VisualTree;
using Avalonia.Interactivity;
using BControl.Desktop.ViewModels;
using BControl.Desktop.Views;

namespace BControl.Desktop;
public partial class MainWindow : Window
{
    public Func<Task>? ReloadVault { get; set; }
    private readonly List<CredentialWindow> _credentialWindows = [];
    private VaultConflictsWindow? _vaultConflictWindow;
    private Task _vaultDialogCompletion = Task.CompletedTask;
    public async Task<bool> PrepareVaultDialogForQuitAsync()
    {
        if (_vaultConflictWindow is not { } dialog) return true;
        if (dialog.IsApplying) return false;
        dialog.Close(); await _vaultDialogCompletion; return true;
    }
    public MainWindow()
    {
        App.LogStatic("MainWindow ctor 开始");
        InitializeComponent();
        helpMenu.IsVisible = OperatingSystem.IsWindows();
        App.LogStatic("MainWindow ctor 完成");
        DataContextChanged += (_, _) =>
        {
            if (DataContext is MainViewModel vm)
            {
                vm.PromptCredential = PromptCredentialAsync;
                vm.ConfirmPrivate = async (_, cancellation) => await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => ConfirmDialog.ShowAsync(this, Loc.T("kvm.privateConfirmation"), cancellation));
            }
        };
        Opened += async (_, _) =>
        {
            App.LogStatic("窗口已打开");
            if (DataContext is MainViewModel vm)
                vm.SetVisible(true);
            await ViewModel.RefreshAsync();
        };
        PropertyChanged += (_, args) =>
        {
            if (args.Property == WindowStateProperty && DataContext is MainViewModel vm)
                vm.SetVisible(WindowState != WindowState.Minimized);
        };
        Closed += (_, _) =>
        {
            if (DataContext is MainViewModel vm)
                vm.SetVisible(false);
        };
    }

    private async Task<StoredCredential?> PromptCredentialAsync(ServerRecord record, bool authenticationFailed)
    {
        var model = ViewModel;
        if (!model.IsOperational) return null;
        var prompt = new CredentialWindow(record.Username, authenticationFailed ? Loc.T("credential.authFailedNotice") : record.Name);
        _credentialWindows.Add(prompt);
        try {
            var result = await prompt.ShowDialog<CredentialInput?>(this);
            if (result == null || !model.IsOperational || !ReferenceEquals(DataContext, model)) return null;
            await model.SaveCredentialAsync(record, result.Credential, result.Save);
            return result.Credential;
        }
        finally { _credentialWindows.Remove(prompt); }
    }

    public async Task<bool> ConfirmQuitAsync()
    {
        if (!ViewModel.HasLocalMedia)
            return true;
        if (!await ConfirmDialog.ShowAsync(this, Loc.T("media.quitLocalConfirm")))
            return false;
        return await ViewModel.EjectLocalMediaAsync();
    }

    private MainViewModel ViewModel => (MainViewModel)DataContext!;

    private void OnHome(object? sender, RoutedEventArgs e) => ViewModel.SelectedTab = ViewModel;
    private void OnCloseWindow(object? sender, RoutedEventArgs e) => Close();
    private async void OnAbout(object? sender, RoutedEventArgs e) => await new AboutWindow().ShowDialog(this);
    private async void OnVaultPassword(object? sender, RoutedEventArgs e)
    {
        if (ViewModel.IsOperational && ViewModel.SupportsMasterPasswordChange)
            await new VaultPasswordWindow(ViewModel.ChangeMasterPasswordAsync).ShowDialog(this);
    }
    private async void OnVaultConflicts(object? sender, RoutedEventArgs e)
    {
        var model = ViewModel; var stopped = false;
        var dialog = new VaultConflictsWindow(model.VaultStore, async owner => {
            if (model.HasLocalMedia && !await ConfirmDialog.ShowAsync(owner, Loc.T("media.quitLocalConfirm"))) return false;
            if (!await model.EjectLocalMediaAsync()) throw new InvalidOperationException(Loc.T("media.removalUnconfirmed"));
            foreach (var prompt in _credentialWindows.ToArray()) prompt.Close();
            await model.StopForVaultChangeAsync(); stopped = true; return true;
        }, record => {
            static string Reference(string value) => Guid.TryParse(value, out var id) ? id.ToString("N") : value;
            var value = record[(record.IndexOf(':') + 1)..];
            var row = model.Servers.FirstOrDefault(item => record.StartsWith("device:", StringComparison.Ordinal)
                ? Reference(item.Record.ServerId) == Reference(value)
                : record.StartsWith("credential:", StringComparison.Ordinal) &&
                    (Reference(item.Record.CredentialRef ?? "") == Reference(value) || Reference(item.Record.Proxy?.CredentialRef ?? "") == Reference(value)));
            return row == null ? Loc.T("vault.record") + " · " + value[..Math.Min(8, value.Length)] : string.IsNullOrEmpty(row.Record.Name) ? row.Record.Address : row.Record.Name;
        });
        var completed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _vaultDialogCompletion = completed.Task; _vaultConflictWindow = dialog;
        try {
            await dialog.ShowDialog(this);
            if (!stopped) { if (!model.IsOperational) model.StatusMessage = Loc.T("vault.connectionsNotClosed"); return; }
            try {
                if (ReloadVault == null) throw new InvalidOperationException(Loc.T("vault.unavailable"));
                await ReloadVault();
                if (dialog.Applied) ViewModel.StatusMessage = Loc.T(dialog.CleanupComplete ? "vault.applied" : "vault.cleanupPending");
            }
            catch (Exception error) { ViewModel.StatusMessage = VaultMessages.Describe(error); }
        }
        finally { _vaultConflictWindow = null; completed.TrySetResult(); }
    }

    private async void OnRefresh(object? sender, RoutedEventArgs e) => await ViewModel.RefreshAsync();
    private async void OnAddServer(object? sender, RoutedEventArgs e)
    {
        var wizard = new AddWizardWindow();
        var vm = new AddWizardViewModel(async (record, credential, verified, proxyCredential) =>
        {
            await ViewModel.AddServerAsync(record, credential, verified, proxyCredential);
        });
        wizard.DataContext = vm;
        await wizard.ShowDialog(this);
    }

    private void OnSolMenu(object? sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem { Tag: string action } || ViewModel.SelectedWorkspace?.Content is not SolWorkspaceViewModel)
            return;
        var view = this.GetVisualDescendants().OfType<SolWorkspaceView>().FirstOrDefault();
        view?.RaiseEvent(new KeysMenuActionEventArgs(action));
    }

    private async void OnClearLog(object? sender, RoutedEventArgs e)
    {
        if (!await ConfirmDialog.ShowAsync(this, Loc.T("log.clearBody")))
            return;
        try
        {
            CoreLog.Clear();
        }
        catch (Exception ex)
        {
            ViewModel.StatusMessage = ex.Message;
        }
    }

    private void OnLogLevel(object? sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem { Tag: string value } || !uint.TryParse(value, out var level))
            return;
        try
        {
            CoreLog.Configure(level);
        }
        catch (Exception ex)
        {
            ViewModel.StatusMessage = ex.Message;
        }
    }

    private async void OnOpenLogFolder(object? sender, RoutedEventArgs e)
    {
        try
        {
            Directory.CreateDirectory(CoreLog.DirectoryPath);
            var folder = await StorageProvider.TryGetFolderFromPathAsync(CoreLog.DirectoryPath);
            if (folder != null)
                await Launcher.LaunchDirectoryInfoAsync(new DirectoryInfo(CoreLog.DirectoryPath));
        }
        catch (Exception ex)
        {
            ViewModel.StatusMessage = ex.Message;
        }
    }

    private async void OnExportLog(object? sender, RoutedEventArgs e)
    {
        var anonymized = sender is MenuItem { Tag: "anonymized" };
        if (!anonymized && !await ConfirmDialog.ShowAsync(this, Loc.T("log.rawWarningBody")))
            return;
        try
        {
            var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions { Title = Loc.T("log.export"), SuggestedFileName = "bcontrol.log" });
            if (file == null)
                return;
            using (file)
            {
                var contents = await Task.Run(() => anonymized ? DiagnosticExport.Anonymize(CoreLog.Read()) : CoreLog.Read());
                await using var stream = await file.OpenWriteAsync();
                stream.SetLength(0);
                await using var writer = new StreamWriter(stream);
                await writer.WriteAsync(contents);
            }

            ViewModel.StatusMessage = Loc.T("log.exported");
        }
        catch (Exception ex)
        {
            ViewModel.StatusMessage = Loc.T("log.exportFailed") + " " + ex.Message;
        }
    }

    private async void OnImport(object? sender, RoutedEventArgs e)
    {
        try
        {
            var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = Loc.T("common.import"), AllowMultiple = false, FileTypeFilter = new[] { new FilePickerFileType("JSON / CSV") { Patterns = new[] { "*.json", "*.csv" } } }, });
            if (files.Count == 0)
                return;
            using var file = files[0];
            await using var stream = await file.OpenReadAsync();
            using var data = new MemoryStream();
            var buffer = new byte[8192];
            int count;
            while ((count = await stream.ReadAsync(buffer)) > 0)
            {
                if (data.Length + count > 1024 * 1024)
                    throw new InvalidDataException(Loc.T("import.limit"));
                await data.WriteAsync(buffer.AsMemory(0, count));
            }

            var bytes = data.ToArray();
            var format = Path.GetExtension(file.Name).Equals(".csv", StringComparison.OrdinalIgnoreCase) ? InventoryParser.FormatCsv : InventoryParser.FormatJson;
            var result = await Task.Run(() => InventoryParser.Parse(bytes, format));
            var updateNames = await new ImportWindow
            {
                DataContext = result.Entries
            }.ShowDialog<bool?>(this);
            if (updateNames.HasValue)
                await ViewModel.ImportAsync(result.Entries, updateNames.Value);
        }
        catch (Exception ex)
        {
            ViewModel.StatusMessage = ex.Message;
        }
    }

    private async void OnCloseTab(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: WorkspaceTab tab })
        {
            // 媒体页有挂载时询问保留/弹出/取消。
            if (tab.Content is MediaWorkspaceViewModel { HasActiveMount: true } media)
            {
                var dialog = new MediaCloseDialog();
                var choice = await dialog.ShowDialog<MediaCloseChoice?>(this);
                if (choice == null || choice == MediaCloseChoice.Cancel)
                    return;
                if (choice == MediaCloseChoice.EjectAndClose)
                {
                    await media.EjectLocalAsync();
                    foreach (var device in media.Devices.Where(d => d.Inserted && media.Owns(d)).ToList())
                        await media.EjectAsync(device.Device);
                    if (media.HasActiveMount)
                    {
                        // 弹出失败/未知：保留状态，不关闭。
                        var retry = new MediaCloseDialog(Loc.T("media.ejectPartial"));
                        var second = await retry.ShowDialog<MediaCloseChoice?>(this);
                        if (second != MediaCloseChoice.KeepMounted)
                            return;
                    }
                }
            // KeepMounted：状态保留在设备侧，允许关闭页面。
            }

            await ViewModel.CloseWorkspaceAsync(tab);
        }
    }
}
