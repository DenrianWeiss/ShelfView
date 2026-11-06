using Avalonia.Controls;
using Avalonia.Interactivity;
using BControl.Core.Localization;
using BControl.Core.Storage;
using BControl.Desktop.Services;

namespace BControl.Desktop.Views;
public partial class VaultUnlockWindow : Window
{
    private readonly string _legacyPath, _vaultPath;
    private readonly ICredentialStore _legacy;
    private readonly Func<VaultStorageSession, Task> _opened;
    private readonly CancellationTokenSource _lifetime = new();
    private bool _new, _busy, _finished;
    public VaultUnlockWindow() : this(ServerStore.DefaultPath(), _ => Task.CompletedTask) { }
    public VaultUnlockWindow(string legacyPath, Func<VaultStorageSession, Task> opened)
    {
        InitializeComponent(); _legacyPath = legacyPath; _vaultPath = Path.Combine(Path.GetDirectoryName(legacyPath)!, "vault.bcv");
        _legacy = CredentialService.CreateLegacyStore(); _opened = opened;
        Opened += async (_, _) => await TryAutomaticAsync();
        Closing += (_, _) => { if (!_finished) _lifetime.Cancel(); Password.Text = ""; ConfirmPassword.Text = ""; };
    }
    private void Busy(bool value) { _busy = value; Unlock.IsEnabled = !value; Password.IsEnabled = !value; ConfirmPassword.IsEnabled = !value; Progress.IsVisible = value; }
    private void ShowPrompt()
    {
        _new = !File.Exists(_vaultPath); Confirmation.IsVisible = _new;
        Heading.Text = Loc.T(_new ? "vault.create" : "vault.unlock");
        Unlock.Content = Heading.Text; Password.Focus();
    }
    private async Task TryAutomaticAsync()
    {
        ShowPrompt(); if (_new) return;
        Busy(true);
        try {
            var session = await VaultStorageSession.TryAutoOpenAsync(_vaultPath, _lifetime.Token);
            if (session != null) await CompleteAsync(session);
        }
        catch (OperationCanceledException) { }
        catch (Exception error) { Status.Text = VaultMessages.Describe(error); }
        finally { Busy(false); }
    }
    private async void OnUnlock(object? sender, RoutedEventArgs e)
    {
        if (_busy || string.IsNullOrEmpty(Password.Text)) return;
        if (_new && Password.Text != ConfirmPassword.Text) { Status.Text = Loc.T("vault.passwordMismatch"); return; }
        var password = Password.Text; Password.Text = ""; ConfirmPassword.Text = ""; Status.Text = ""; Busy(true);
        try {
            VaultStorageSession session;
            if (_new) {
                var migration = await Task.Run(() => VaultMigration.PrepareAsync(_legacyPath, _legacy, _lifetime.Token));
                session = await VaultStorageSession.CreateAsync(_vaultPath, password,
                    id => VaultApplicationStore.BuildMigration(id, migration.Inventory, migration.Credentials, migration.Pending, migration.LegacyHash), _lifetime.Token);
            } else session = await VaultStorageSession.OpenWithPasswordAsync(_vaultPath, password, _lifetime.Token);
            await CompleteAsync(session);
        }
        catch (OperationCanceledException) { }
        catch (Exception error) { Status.Text = VaultMessages.Describe(error); ShowPrompt(); }
        finally { Busy(false); }
    }
    private async Task CompleteAsync(VaultStorageSession session)
    {
        try {
            _lifetime.Token.ThrowIfCancellationRequested();
            var store = new VaultApplicationStore(session);
            await Task.Run(() => store.FinishMigrationAsync(_legacyPath, _legacy, _lifetime.Token));
            _lifetime.Token.ThrowIfCancellationRequested();
            await _opened(session); _finished = true; Close();
        }
        catch { await session.DisposeAsync(); throw; }
    }
    private void OnCancel(object? sender, RoutedEventArgs e) => Close();
}
