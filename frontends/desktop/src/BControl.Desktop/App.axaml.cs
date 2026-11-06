using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using BControl.Desktop.Services;
using BControl.Desktop.ViewModels;

namespace BControl.Desktop;
public partial class App : Application
{
    public static void LogStatic(string message) => System.Diagnostics.Trace.WriteLine(message);
    private static void Log(string message) => LogStatic(message);
    public override void Initialize()
    {
        Log("Initialize 开始");
        AvaloniaXamlLoader.Load(this);
        Log("Initialize 完成");
    }

    public MainViewModel? MainViewModel { get; private set; }

    public override void OnFrameworkInitializationCompleted()
    {
        try
        {
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                desktop.MainWindow = new Views.VaultUnlockWindow(ServerStore.DefaultPath(), async session =>
                {
                    var vault = new VaultApplicationStore(session);
                    var store = new ServerStore(vault, session.FilePath);
                    var inventory = await store.LoadAsync();
                    MainViewModel = new MainViewModel(store, new CredentialService(vault), inventory);
                    var window = new MainWindow { DataContext = MainViewModel };
                    window.ReloadVault = async () => {
                        await store.ReloadCurrentAsync();
                        var reloaded = await store.LoadAsync();
                        MainViewModel = new MainViewModel(store, new CredentialService(vault), reloaded, automaticRefresh: false);
                        window.DataContext = MainViewModel;
                    };
                    desktop.MainWindow = window;
                    var shuttingDown = false;
                    var confirming = false;
                    async Task ShutdownAsync()
                    {
                        if (shuttingDown || confirming) return;
                        confirming = true;
                        try {
                            if (!await window.PrepareVaultDialogForQuitAsync()) return;
                            if (!await window.ConfirmQuitAsync()) return;
                            shuttingDown = true;
                            try { await MainViewModel.DisposeAsync(); }
                            finally { await session.DisposeAsync(); desktop.Shutdown(); }
                        }
                        catch (Exception error) { Log("关闭失败: " + error.GetType().Name); }
                        finally { confirming = false; }
                    }
                    desktop.ShutdownRequested += (_, e) => { if (!shuttingDown) { e.Cancel = true; _ = ShutdownAsync(); } };
                    window.Closing += (_, e) => { if (!shuttingDown) { e.Cancel = true; _ = ShutdownAsync(); } };
                    window.Show();
                });
            }

            base.OnFrameworkInitializationCompleted();
        }
        catch (Exception ex)
        {
            Log($"启动失败: {ex.GetType().Name}\n{ex.StackTrace}");
            throw;
        }
    }
}
