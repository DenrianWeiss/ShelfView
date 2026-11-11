using Avalonia.Controls;
using BControl.Desktop.Services;
using BControl.Desktop.ViewModels;

namespace BControl.Desktop.Tests;

[Collection("Avalonia UI")]
public sealed class DeviceEditTests
{
    [Fact]
    public async Task AddFormShowsEditableNameBeforeAnyProbe()
    {
        using var ui = Avalonia.Headless.HeadlessUnitTestSession.StartNew(typeof(KvmTestApp));
        await ui.Dispatch(() => {
            var model = new AddWizardViewModel((_, _, _, _) => Task.CompletedTask) { ProtocolChoice = 2 };
            var window = new BControl.Desktop.Views.AddWizardWindow { DataContext = model };
            window.Show();
            try {
                Avalonia.Threading.Dispatcher.UIThread.RunJobs();
                var name = window.FindControl<TextBox>("DisplayName")!;
                Assert.True(name.IsEffectivelyVisible); Assert.True(name.IsEffectivelyEnabled);
                name.Text = "Rack 1";
                Assert.Equal("Rack 1", model.DisplayName);
            } finally { window.Close(); }
        }, CancellationToken.None);
    }

    [Theory]
    [InlineData("https://bmc:8443", 2u, "ipmi://bmc")]
    [InlineData("ipmi://bmc:6623", 1u, "https://bmc")]
    [InlineData("https://[2001:db8::1]:8443", 2u, "ipmi://[2001:db8::1]")]
    [InlineData("ipmi://bmc:6623", 2u, "ipmi://bmc:6623")]
    public void ProtocolSwitchDoesNotReuseOtherTransportPort(string input, uint mode, string expected) =>
        Assert.Equal(expected, DeviceAddress.ForProtocol(input, mode));

    [Fact]
    public async Task NameIsEditableImmediatelyAndExistingRmcpCanBeRenamedOffline()
    {
        ServerRecord? saved = null;
        var draft = new AddWizardViewModel((record, _, _, _) => { saved = record; return Task.CompletedTask; });
        Assert.True(draft.CanEditName);
        var original = new ServerRecord { ServerId = "first", Address = "ipmi://bmc:6623", Protocol = 2, Username = "user", Name = "old" };
        draft.LoadForEdit(original, null, null);
        Assert.Equal("", draft.Password);
        Assert.True(draft.KeepPassword);
        Assert.False(draft.ConnectionChanged);
        draft.DisplayName = "new";
        Assert.NotNull(await draft.SaveAsync(false));
        Assert.Equal("new", saved!.Name);
        Assert.Equal(original.Address, saved.Address);
        Assert.Equal("old", original.Name);
        draft.KeepPassword = false;
        Assert.Null(await draft.SaveAsync(false));
    }

    [Fact]
    public async Task CredentialsUpdateGroupWhileAddressAndNameUpdateOnlySelectedDevice()
    {
        var directory = Path.Combine(Path.GetTempPath(), "device-edit-" + Guid.NewGuid().ToString("N"));
        try {
            await using var vault = await TestVault.CreateAsync(directory);
            var original = new ServerRecord { ServerId = "first", EndpointId = "bmc", Address = "https://bmc", Protocol = 1, Username = "old", SystemUri = "/redfish/v1/Systems/1" };
            var second = new ServerRecord { ServerId = "second", EndpointId = "bmc", Address = "https://bmc", Protocol = 1, Username = "old", SystemUri = "/redfish/v1/Systems/2" };
            await vault.Store.SaveAsync(new InventoryFile { Servers = [original, second] });
            await using var model = new MainViewModel(vault.Store, new CredentialService(new UnavailableCredentialStore()), automaticRefresh: false);
            var replacement = new ServerRecord { Address = "ipmi://other", Name = "renamed", Protocol = 2 };
            await model.EditServerAsync(model.Servers.Single(r => r.ServerId == "first").Record, replacement, new("new-user", "test-secret"));
            var saved = (await vault.Store.LoadAsync()).Servers;
            var one = saved.Single(r => r.ServerId == "first"); var two = saved.Single(r => r.ServerId == "second");
            Assert.Equal("renamed", one.Name); Assert.Equal("ipmi://other", one.Address);
            Assert.Equal("https://bmc", two.Address); Assert.Equal("", two.Name);
            Assert.NotEqual(one.EndpointId, two.EndpointId);
            Assert.Equal("new-user", two.Username); Assert.Equal(one.CredentialRef, two.CredentialRef);
            var secret = await vault.Credentials.ReadCredentialAsync(one.CredentialRef, one.Username, default);
            Assert.Equal(new StoredCredential("new-user", "test-secret"), secret);
            Assert.DoesNotContain("test-secret", await File.ReadAllTextAsync(vault.Store.FilePath));
        } finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
    }
}
