using BControl.Core.Redfish;
using BControl.Desktop.Services;
using BControl.Desktop.ViewModels;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace BControl.Desktop.Tests;
public sealed class AddWizardTests
{
    [Fact]
    public async Task FailedTlsProbeReenablesEditingBeforeCertificateDiagnosticsFinish()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        var model = CreateModel(new FakeWizardSave());
        model.Address = $"https://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}";
        model.Username = "test";
        model.ProtocolChoice = 1;
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(6));
        var probe = model.ProbeAsync();
        try
        {
            Assert.False(model.IsNotProbing);
            using (var first = await listener.AcceptTcpClientAsync(budget.Token))
            using (var tls = new SslStream(first.GetStream()))
            {
                try { await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate }, budget.Token); }
                catch (System.Security.Authentication.AuthenticationException) { }
                catch (IOException) { }
            }
            using var diagnostic = await listener.AcceptTcpClientAsync(budget.Token);
            // Keep the diagnostic socket open without completing TLS.
            await probe.WaitAsync(budget.Token);
            Assert.True(model.IsNotProbing);
            Assert.NotEmpty(model.FailureMessage);
            model.MinimumTlsIndex = 1;
            Assert.Equal(AddWizardViewModel.WizardStep.Input, model.Step);
        }
        finally { model.CancelProbe(); }
    }

    [Fact]
    public async Task ProxySecretIsPassedSeparatelyFromSavedRecord()
    {
        ServerRecord? saved = null;
        StoredCredential? secret = null;
        var model = new AddWizardViewModel((record, _, _, proxyCredential) =>
        {
            saved = record; secret = proxyCredential; return Task.CompletedTask;
        }) { Address = "https://bmc.invalid", Username = "bmc-user", ProxyEnabled = true,
            ProxyHost = "127.0.0.1", ProxyPort = "1081", ProxyAuthenticate = true,
            ProxyUsername = "proxy-user", ProxyPassword = "test-proxy-password" };
        Assert.NotNull(await model.SaveAsync(true));
        Assert.Equal("proxy-user", saved!.Proxy!.Username);
        Assert.False(string.IsNullOrEmpty(saved.Proxy.CredentialRef));
        Assert.Equal("test-proxy-password", secret!.Password);
        Assert.DoesNotContain("test-proxy-password", System.Text.Json.JsonSerializer.Serialize(saved));
        model.Systems.Add(new WizardSystemItem(new DiscoveredSystem("/redfish/v1/Systems/1", "A", "M", "X", "h", 1, "On")));
        model.ProxyHost = "127.0.0.2";
        Assert.Empty(model.Systems);
        Assert.Equal(AddWizardViewModel.WizardStep.Input, model.Step);
    }

    [Fact]
    public async Task InvalidProxyFailsBeforeProbeOrSave()
    {
        var save = new FakeWizardSave();
        var model = CreateModel(save);
        model.Address = "https://bmc.invalid"; model.Username = "user";
        model.ProxyEnabled = true; model.ProxyHost = "127.0.0.1"; model.ProxyPort = "0";
        await model.ProbeAsync();
        Assert.NotEmpty(model.FailureMessage);
        Assert.Equal(AddWizardViewModel.WizardStep.Input, model.Step);
        await Assert.ThrowsAsync<BControl.Core.Native.BcException>(() => model.SaveAsync(true));
        Assert.Empty(save.Saved);
    }

    private sealed class FakeWizardSave
    {
        public List<(ServerRecord Record, StoredCredential Credential, bool Verified)> Saved { get; } = new();

        public Task Save(ServerRecord record, StoredCredential credential, bool verified)
        {
            Saved.Add((record, credential, verified));
            return Task.CompletedTask;
        }
    }

    private static AddWizardViewModel CreateModel(FakeWizardSave save) => new((record, credential, verified, _) => save.Save(record, credential, verified));
    [Theory]
    [InlineData(0u, 0)]
    [InlineData(1u, 2)]
    [InlineData(2u, 2)]
    public async Task CompatibilityPolicyNeedsConfirmationAndIsSavedPerServer(uint policy, int minimumIndex)
    {
        var save = new FakeWizardSave();
        var model = CreateModel(save);
        model.Address = "https://fixture.invalid";
        model.Username = "fixture";
        model.CertPolicy = policy;
        model.MinimumTlsIndex = minimumIndex;
        Assert.Null(await model.SaveAsync(true));
        Assert.Empty(save.Saved);
        model.SecurityConfirmed = true;
        var record = await model.SaveAsync(true);
        Assert.NotNull(record);
        Assert.Equal((uint)(minimumIndex + 10), record.MinimumTls);
        Assert.Equal(policy, record.CertPolicy);
    }

    [Fact]
    public void MultiSystem_RequiresExplicitSelection()
    {
        var save = new FakeWizardSave();
        var model = CreateModel(save);
        model.Systems.Add(new WizardSystemItem(new DiscoveredSystem("/redfish/v1/Systems/A", "A", "M", "X", "h", 1, "On")));
        model.Systems.Add(new WizardSystemItem(new DiscoveredSystem("/redfish/v1/Systems/B", "B", "M", "X", "h", 1, "On")));
        // 多系统且无显式选择时拒绝保存。
        Assert.True(model.MultipleSystems);
    }

    [Fact]
    public async Task SaveUnverified_RecordsFailure_WithoutFakingOnline()
    {
        var save = new FakeWizardSave();
        var model = CreateModel(save);
        model.Address = "https://unreachable.invalid";
        model.Username = "op";
        model.Password = "pw";
        var record = await model.SaveAsync(saveUnverified: true);
        Assert.NotNull(record);
        Assert.False(record!.Verified);
        Assert.False(string.IsNullOrEmpty(record.VerificationError));
        Assert.Equal("https://unreachable.invalid", save.Saved.Single().Record.Address);
    }

    [Fact]
    public async Task SaveWithoutUnverifiedFlag_FailsWhenProbeFailed()
    {
        var save = new FakeWizardSave();
        var model = CreateModel(save);
        model.Address = "https://unreachable.invalid";
        model.Username = "op";
        var record = await model.SaveAsync(saveUnverified: false);
        Assert.Null(record);
        Assert.Empty(save.Saved);
    }

    [Fact]
    public void AddressParsing_HandlesSchemesIpv6AndPorts()
    {
        Assert.Equal(("bmc.local", (ushort)623), SolWorkspaceViewModel.ParseAddress("bmc.local", 2));
        Assert.Equal(("bmc.local", (ushort)664), SolWorkspaceViewModel.ParseAddress("ipmi://bmc.local:664", 2));
        Assert.Equal(("2001:db8::1", (ushort)623), SolWorkspaceViewModel.ParseAddress("2001:db8::1", 2));
        Assert.Equal(("bmc.local", (ushort)623), SolWorkspaceViewModel.ParseAddress("https://bmc.local", 1));
    }
}
