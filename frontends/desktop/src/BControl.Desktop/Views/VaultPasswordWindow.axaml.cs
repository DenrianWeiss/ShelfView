using Avalonia.Controls;
using Avalonia.Interactivity;
using BControl.Core.Localization;
using BControl.Desktop.Services;

namespace BControl.Desktop.Views;
public partial class VaultPasswordWindow : Window
{
    private readonly Func<string, CancellationToken, Task> _save;
    private readonly CancellationTokenSource _lifetime = new();
    private bool _busy;
    public VaultPasswordWindow() : this((_, _) => Task.CompletedTask) { }
    public VaultPasswordWindow(Func<string, CancellationToken, Task> save)
    {
        InitializeComponent(); _save = save;
        Closed += (_, _) => { _lifetime.Cancel(); Password.Text = ""; Confirmation.Text = ""; };
    }
    private async void OnSave(object? sender, RoutedEventArgs e)
    {
        if (_busy || string.IsNullOrEmpty(Password.Text)) return;
        if (Password.Text != Confirmation.Text) { Status.Text = Loc.T("vault.passwordMismatch"); return; }
        var secret = Password.Text; Password.Text = ""; Confirmation.Text = ""; Status.Text = "";
        _busy = true; Save.IsEnabled = false; Password.IsEnabled = false; Confirmation.IsEnabled = false; Progress.IsVisible = true;
        try { await _save(secret, _lifetime.Token); Close(); }
        catch (OperationCanceledException) { }
        catch (Exception error) { Status.Text = VaultMessages.Describe(error); }
        finally { _busy = false; Save.IsEnabled = true; Password.IsEnabled = true; Confirmation.IsEnabled = true; Progress.IsVisible = false; }
    }
    private void OnCancel(object? sender, RoutedEventArgs e) => Close();
}
