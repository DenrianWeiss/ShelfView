using Avalonia.Controls;
using Avalonia.Interactivity;
using BControl.Desktop.Services;

namespace BControl.Desktop.Views;
public sealed record CredentialInput(StoredCredential Credential, bool Save);
public partial class CredentialWindow : Window
{
    public CredentialWindow() => InitializeComponent();
    public CredentialWindow(string username, string notice) : this()
    {
        Username.Text = username;
        Notice.Text = notice;
    }

    private void OnCancel(object? sender, RoutedEventArgs e) => Close((CredentialInput? )null);
    private void OnConnect(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(Username.Text))
            return;
        var credential = new StoredCredential(Username.Text, Password.Text ?? "");
        Password.Text = "";
        Close(new CredentialInput(credential, SaveCredential.IsChecked == true));
    }
}
