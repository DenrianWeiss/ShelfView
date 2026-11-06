using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Interactivity;
using Avalonia.Threading;
using BControl.Desktop.Services;
using BControl.Desktop.ViewModels;
using BControl.Desktop.Views;

namespace BControl.Desktop.Tests;

[Collection("Avalonia UI")]
public sealed class ServerProxyViewTests
{
    [Fact]
    public async Task WindowGatesInputsAndSavesSeparateCredentials()
    {
        using var ui = HeadlessUnitTestSession.StartNew(typeof(KvmTestApp));
        await ui.Dispatch(async () =>
        {
            var directory = Path.Combine(Path.GetTempPath(), "bcontrol-proxy-view-" + Guid.NewGuid().ToString("N"));
            await using var vault = await TestVault.CreateAsync(directory);
            var store = vault.Store;
            var credentials = new CredentialService(new UnavailableCredentialStore());
            await store.SaveAsync(new InventoryFile { Servers = [new ServerRecord { ServerId = "test", Address = "https://fixture.invalid", Username = "fixture" }] });
            try
            {
                await using var model = new MainViewModel(store, credentials);
                model.SetVisible(false);
                var record = model.Servers[0].Record;
                var window = new ServerProxyWindow(model, record, null);
                window.Show();
                try
                {
                    Dispatcher.UIThread.RunJobs();
                    var host = window.FindControl<TextBox>("Host")!;
                    var password = window.FindControl<TextBox>("Password")!;
                    Assert.False(host.IsEffectivelyEnabled);
                    window.FindControl<CheckBox>("Enabled")!.IsChecked = true;
                    Dispatcher.UIThread.RunJobs();
                    Assert.True(host.IsEffectivelyEnabled);
                    Assert.False(password.IsEffectivelyEnabled);
                    window.FindControl<CheckBox>("Authenticate")!.IsChecked = true;
                    Dispatcher.UIThread.RunJobs();
                    Assert.True(password.IsEffectivelyEnabled);
                    host.Text = "127.0.0.1";
                    window.FindControl<TextBox>("Port")!.Text = "1081";
                    window.FindControl<TextBox>("Username")!.Text = "proxy-user";
                    password.Text = "test-secret";
                    window.FindControl<TextBox>("TimeoutSeconds")!.Text = "60";
                    window.FindControl<ComboBox>("CertificatePolicy")!.SelectedIndex = 2;
                    var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    window.Closed += (_, _) => closed.TrySetResult();
                    window.FindControl<Button>("Save")!.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                    Assert.False(closed.Task.IsCompleted);
                    Assert.True(host.IsEffectivelyEnabled);
                    window.FindControl<CheckBox>("SecurityConfirmed")!.IsChecked = true;
                    window.FindControl<Button>("Save")!.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                    await closed.Task.WaitAsync(TimeSpan.FromSeconds(5));
                    Assert.Equal("", password.Text);
                    Assert.Equal((ushort)1081, (await record.ResolveProxyAsync())!.Port);
                    var saved = (await store.LoadAsync()).Servers[0];
                    Assert.Equal(60u, saved.Timeout!.Seconds);
                    Assert.Equal(2u, saved.CertPolicy);
                    Assert.Equal("proxy-user", saved.Proxy!.Username);
                    Assert.DoesNotContain("test-secret", await File.ReadAllTextAsync(store.FilePath));
                    Assert.Equal("test-secret", (await credentials.ReadAsync(saved.Proxy.CredentialRef!, "proxy-user")).Credential!.Password);
                    var rename = new ServerProxyWindow(model, record, null);
                    rename.Show();
                    try
                    {
                        var nameChanged = false;
                        model.Servers[0].PropertyChanged += (_, e) => nameChanged |= e.PropertyName == nameof(ServerRowViewModel.Name);
                        rename.FindControl<TextBox>("DisplayName")!.Text = " Rack 2 ";
                        var renamed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                        rename.Closed += (_, _) => renamed.TrySetResult();
                        rename.FindControl<Button>("Save")!.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                        await renamed.Task.WaitAsync(TimeSpan.FromSeconds(5));
                        Assert.True(nameChanged);
                        Assert.Equal("Rack 2", model.Servers[0].Name);
                        var renamedRecord = (await store.LoadAsync()).Servers[0];
                        Assert.Equal("Rack 2", renamedRecord.Name);
                        Assert.Equal(saved.Proxy.CredentialRef, renamedRecord.Proxy!.CredentialRef);
                    }
                    finally { rename.Close(); }
                    await model.SaveProxyAsync(record, null, 1080, null);
                    Assert.Null(record.Proxy);
                    Assert.Equal(60u, record.Timeout!.Seconds);
                    await model.SaveProxyAsync(record, null, 1080, null, null);
                    Assert.Null((await store.LoadAsync()).Servers[0].Timeout);
                    Assert.Null((await credentials.ReadAsync(saved.Proxy.CredentialRef!, "proxy-user")).Credential);
                }
                finally { window.Close(); }
            }
            finally { Directory.Delete(directory, true); }
            return true;
        }, CancellationToken.None);
    }

    [Fact]
    public async Task FailedSaveRestoresPreviousProxyAndCredential()
    {
        using var ui = HeadlessUnitTestSession.StartNew(typeof(KvmTestApp));
        await ui.Dispatch(async () =>
        {
            var directory = Path.Combine(Path.GetTempPath(), "bcontrol-proxy-rollback-" + Guid.NewGuid().ToString("N"));
            await using var vault = await TestVault.CreateAsync(directory);
            var store = vault.Store;
            var credentials = new CredentialService(new UnavailableCredentialStore());
            await store.SaveAsync(new InventoryFile { Servers = [new ServerRecord { ServerId = "test", Address = "https://fixture.invalid", Username = "fixture" }] });
            try
            {
                await using var model = new MainViewModel(store, credentials);
                model.SetVisible(false);
                var record = model.Servers[0].Record;
                await model.SaveProxyAsync(record, "127.0.0.1", 1080, new("proxy-user", "old-secret"));
                var previous = record.Proxy;
                var originalVault = await File.ReadAllBytesAsync(store.FilePath);
                File.Delete(store.FilePath);
                Directory.CreateDirectory(store.FilePath);
                try
                {
                    var failure = await Record.ExceptionAsync(() => model.SaveProxyAsync(record, "127.0.0.2", 1081, new("new-user", "new-secret")));
                    Assert.True(failure is IOException or UnauthorizedAccessException or BControl.Core.Storage.VaultChangedException);
                    Assert.Same(previous, record.Proxy);
                    Assert.Equal("old-secret", (await credentials.ReadAsync(previous!.CredentialRef!, "proxy-user")).Credential!.Password);
                }
                finally { Directory.Delete(store.FilePath); await File.WriteAllBytesAsync(store.FilePath, originalVault); }
            }
            finally { Directory.Delete(directory, true); }
            return true;
        }, CancellationToken.None);
    }
}
