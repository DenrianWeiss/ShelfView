using BControl.Core.Native;
using BControl.Core.Redfish;
using BControl.Core.Media;
using BControl.Core.Storage;
using System.Text;

namespace BControl.Integration.Tests;
/// <summary>HTTPS Redfish 夹具：登录/发现/系统/电源/传感器与概况汇总。</summary>
public sealed class RedfishBindingTests : IAsyncLifetime
{
    private FixtureProcess? _fixture;
    public async Task InitializeAsync() => _fixture = await FixtureProcess.StartAsync("redfish_fixture.py", "0");
    public async Task DisposeAsync()
    {
        _fixture?.Dispose();
        await Task.CompletedTask;
    }

    private string Address => $"https://127.0.0.1:{_fixture!.Port}";
    private DeviceCredential Credential => new("fixture-user", "fixture-password");

    [Theory]
    [InlineData("invalid-source", false, 0)]
    [InlineData("https://images.invalid/rejected.iso", false, 403)]
    [InlineData("https://images.invalid/uncertain.iso", true, 500)]
    public async Task MediaInsertFailure_ClearsOnlyDefinitelyUnsubmittedOrRejectedWrites(string image, bool uncertain, int httpStatus)
    {
        const string uri = "/redfish/v1/Managers/media/VirtualMedia/cd";
        var directory = Path.Combine(Path.GetTempPath(), "bcontrol-media-failure-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        using var keys = new MediaKeys();
        try {
            var path = Path.Combine(directory, "vault.bcv");
            await using var vault = await VaultStorageSession.CreateAsync(path, "fixture master password", keyStore: keys);
            var store = new VaultRemoteMediaStore(vault, Address, Credential.Username);
            var workspace = new RemoteMediaWorkspace(store);
            await using var client = await RedfishMediaClient.ConnectAsync(Address, Credential, "", Bc.CertSkipAll, 5000, 12, null);
            var error = await Assert.ThrowsAsync<BcException>(() => workspace.InsertAsync(client, uri, image, true, 15000));
            Assert.Equal((uint)httpStatus, error.HttpStatus);
            Assert.Equal(uncertain, error.WriteMayHaveTakenEffect);
            Assert.Equal(uncertain, workspace.HasPendingOperations);
            await using var reopened = await VaultStorageSession.OpenWithPasswordAsync(path, "fixture master password", keyStore: keys);
            var records = await new VaultRemoteMediaStore(reopened, Address, Credential.Username).ReadAsync();
            if (uncertain) Assert.Equal(RemoteMediaPhase.Submitting, Assert.Single(records).Phase);
            else Assert.Empty(records);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Theory]
    [InlineData("eject-rejected", false, 403)]
    [InlineData("eject-uncertain", true, 500)]
    [InlineData("eject-readback-failed", true, 500)]
    public async Task MediaEjectFailure_RestoresOwnershipOnlyForDefinitiveRejection(string imageName, bool uncertain, int httpStatus)
    {
        const string uri = "/redfish/v1/Managers/media/VirtualMedia/cd";
        var directory = Path.Combine(Path.GetTempPath(), "bcontrol-eject-failure-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        using var keys = new MediaKeys();
        try {
            var path = Path.Combine(directory, "vault.bcv");
            await using var vault = await VaultStorageSession.CreateAsync(path, "fixture master password", keyStore: keys);
            var store = new VaultRemoteMediaStore(vault, Address, Credential.Username);
            var workspace = new RemoteMediaWorkspace(store);
            await using var client = await RedfishMediaClient.ConnectAsync(Address, Credential, "", Bc.CertSkipAll,
                5000, 12, null, endpointId: Guid.NewGuid());
            Assert.False(await workspace.InsertAsync(client, uri, $"https://images.invalid/{imageName}.iso", true, 15000));
            workspace = new RemoteMediaWorkspace(store);
            await workspace.ReadAsync(client, 15000);
            var mounted = Assert.Single(await store.ReadAsync());
            Assert.Equal(RemoteMediaPhase.Settled, mounted.Phase);
            var error = await Assert.ThrowsAsync<BcException>(() => workspace.EjectAsync(client, uri, 15000));
            Assert.Equal((uint)httpStatus, error.HttpStatus);
            Assert.Equal(uncertain, error.WriteMayHaveTakenEffect);
            Assert.Equal(uncertain, workspace.HasPendingOperations);
            await using var reopened = await VaultStorageSession.OpenWithPasswordAsync(path, "fixture master password", keyStore: keys);
            var current = Assert.Single(await new VaultRemoteMediaStore(reopened, Address, Credential.Username).ReadAsync());
            Assert.NotEqual(mounted.OperationId, current.OperationId);
            Assert.Equal(uncertain ? RemoteMediaAction.Eject : RemoteMediaAction.Insert, current.Action);
            if (!uncertain) {
                Assert.Equal(RemoteMediaPhase.Settled, current.Phase);
                Assert.Equal(mounted.SourceVerification, current.SourceVerification);
                Assert.Equal(mounted.Reference, current.Reference);
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    private sealed class MediaKeys : IVaultKeyStore, IDisposable
    {
        private byte[]? _key;
        public VaultStoredKey? Read(VaultMetadata metadata) => _key == null ? null : new(_key.ToArray(), false);
        public bool Store(VaultMetadata metadata, ReadOnlySpan<byte> key, bool roaming)
        {
            Dispose(); _key = key.ToArray(); return false;
        }
        public void Dispose() { if (_key != null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(_key); _key = null; }
    }

    [Fact]
    public async Task MediaTaskReference_RestoresThroughAdvertisedServiceAndRejectsAnotherEndpoint()
    {
        const string uri = "/redfish/v1/Managers/media/VirtualMedia/cd";
        await using var client = await RedfishMediaClient.ConnectAsync(Address, Credential, "", Bc.CertSkipAll,
            5000, 12, null, endpointId: Guid.NewGuid());
        var write = await client.InsertAsync(uri, "https://images.invalid/private.iso?token=private-token", true, 15000);
        Assert.True(write.Pending);
        Assert.NotNull(write.Reference);
        Assert.DoesNotContain("private-token", Encoding.UTF8.GetString(write.Reference));
        var operation = new RemoteMediaOperation(Guid.NewGuid().ToString("N"), uri, RemoteMediaAction.Insert,
            RemoteMediaPhase.Accepted, write.Reference);
        var task = await client.ResumeTaskAsync(operation, 15000);
        Assert.True(task.Terminal); Assert.False(task.Failed);
        Assert.True(Assert.Single((await client.ReadAsync(15000)).Devices).Inserted);
        await using var other = await RedfishMediaClient.ConnectAsync(Address, Credential, "", Bc.CertSkipAll,
            5000, 12, null, endpointId: Guid.NewGuid());
        var error = await Assert.ThrowsAsync<BcException>(() => other.ResumeTaskAsync(operation, 15000));
        Assert.Equal(Bc.Unsupported, error.Status);
    }

    [Fact]
    public async Task PublicProbe_SurvivesCollectionWhileNativeRequestIsPending()
    {
        using var fixture = await FixtureProcess.StartAsync("redfish_fixture.py", "0", "0", "0.5");
        var completed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task ConnectAsync()
        {
            try
            {
                await RedfishSession.ProbePublicAsync($"https://127.0.0.1:{fixture.Port}", null, Bc.CertSkipAll);
                completed.TrySetResult();
            }
            catch (Exception ex)
            {
                completed.TrySetException(ex);
            }
        }
        _ = ConnectAsync();
        for (var i = 0; i < 10 && !completed.Task.IsCompleted; i++)
        {
            await Task.Delay(30);
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }
        await completed.Task.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task Probe_DiscoversSingleSystem_WithIdentity()
    {
        var result = await DiscoveryService.ProbeAsync(Address, Credential, certPolicy: Bc.CertSkipAll, budgetMilliseconds: 15000);
        var system = Assert.Single(result.Systems);
        Assert.Equal("Fixture system", system.Name);
        Assert.Equal("FixtureVendor", system.Manufacturer);
        Assert.Equal("FixtureModel", system.Model);
        Assert.Equal(Bc.PowerOn, system.PowerState);
        Assert.Equal(Bc.Ok, result.LogoutStatus);
    }

    [Fact]
    public async Task ImportedRecord_DiscoversUniqueSystemForInventory()
    {
        var result = await RedfishManagement.ReadAsync(Address, Credential, "", "inventory", "", Bc.CertSkipAll, default);
        Assert.NotEmpty(result.Items);
        Assert.Equal(Bc.Ok, result.Status);
        Assert.Equal(Bc.Ok, result.LogoutStatus);
    }

    [Fact]
    public async Task Probe_AllowsSlowSessionCleanup()
    {
        using var fixture = await FixtureProcess.StartAsync("redfish_fixture.py", "0", "1.5");
        await using var runtime = RedfishRuntime.Create();
        var result = await DiscoveryService.ProbeAsync($"https://127.0.0.1:{fixture.Port}", Credential,
            certPolicy: Bc.CertSkipAll, budgetMilliseconds: 1500);
        Assert.Single(result.Systems);
        Assert.Equal(Bc.Ok, result.LogoutStatus);
    }

    [Fact]
    public async Task Probe_ReportsBudgetExpiryAsTimeout()
    {
        using var fixture = await FixtureProcess.StartAsync("redfish_fixture.py", "0", "0", "2");
        var error = await Assert.ThrowsAsync<DiscoveryFailure>(() => DiscoveryService.ProbeAsync(
            $"https://127.0.0.1:{fixture.Port}", Credential, certPolicy: Bc.CertSkipAll, budgetMilliseconds: 200));
        Assert.Equal(Bc.Timeout, error.Status);
    }

    [Fact]
    public async Task Overview_RemainingBudgetCapsConfiguredTimeout()
    {
        using var fixture = await FixtureProcess.StartAsync("redfish_fixture.py", "0", "0", "2");
        await using var runtime = RedfishRuntime.Create();
        var error = await Assert.ThrowsAsync<DiscoveryFailure>(() => DiscoveryService.OverviewAsync(
            $"https://127.0.0.1:{fixture.Port}", Credential, systemUri: "/redfish/v1/Systems/host-A",
            certPolicy: Bc.CertSkipAll, budgetMilliseconds: 200, timeout: new BControl.Core.HostTimeout(10)));
        Assert.Equal(Bc.Timeout, error.Status);
    }

    [Fact]
    public async Task Overview_ReturnsCpuAndNormalMaximum()
    {
        var overview = await DiscoveryService.OverviewAsync(Address, Credential, systemUri: "/redfish/v1/Systems/host-A", certPolicy: Bc.CertSkipAll);
        Assert.Equal("Fixture system", overview.System.Name);
        Assert.Equal(Bc.PowerOn, overview.System.PowerState);
        Assert.NotNull(overview.Temperatures.Cpu);
        Assert.Equal("CPU1 temperature", overview.Temperatures.Cpu!.Name);
        Assert.InRange(overview.Temperatures.Cpu.Celsius, 41.0, 42.0);
        Assert.NotNull(overview.Temperatures.NormalMaximum);
        // 正常最高取所有健康温度测点的最大值（41.5 > 22.5）。
        Assert.InRange(overview.Temperatures.NormalMaximum!.Celsius, 41.0, 42.0);
    }

    [Fact]
    public async Task Overview_WrongSystemUri_RequiresSelection()
    {
        await Assert.ThrowsAsync<OverviewException>(() => DiscoveryService.OverviewAsync(Address, Credential, systemUri: "/redfish/v1/Systems/other", certPolicy: Bc.CertSkipAll));
    }

    [Fact]
    public async Task Controls_ReadsPowerActionsAndBootTargets()
    {
        var controls = await DiscoveryService.ReadControlsAsync(Address, Credential, systemUri: "", certPolicy: Bc.CertSkipAll);
        Assert.NotNull(controls.Power);
        Assert.NotEqual(0u, controls.Power!.Value.SupportedResetTypes & (1u << (int)RedfishAbi.ResetForceOff));
        Assert.NotNull(controls.Boot);
        Assert.Equal(Bc.Ok, controls.Boot!.Value.Status);
        Assert.NotEqual(0u, controls.Boot.Value.Flags & BootAbi.TargetsKnown);
        Assert.NotEqual(0u, controls.Boot.Value.SupportedTargets & (1u << (int)BootAbi.Cd));
    }

    [Fact]
    public async Task Power_WriteIsAcceptedAndReadBack()
    {
        await DiscoveryService.PowerAsync(Address, Credential, "/redfish/v1/Systems/host-A", RedfishAbi.ResetForceOff, certPolicy: Bc.CertSkipAll);
        var overview = await DiscoveryService.OverviewAsync(Address, Credential, systemUri: "/redfish/v1/Systems/host-A", certPolicy: Bc.CertSkipAll);
        Assert.Equal(Bc.PowerOff, overview.System.PowerState);
    }

    [Fact]
    public async Task BootOnce_IsVerifiedByReadBack()
    {
        var result = await DiscoveryService.SetBootOnceAsync(Address, Credential, "/redfish/v1/Systems/host-A", BootAbi.Cd, BootAbi.ModeUefi, certPolicy: Bc.CertSkipAll);
        Assert.NotNull(result);
        Assert.NotEqual(0u, result!.Value.Flags & RedfishAbi.BootVerified);
        Assert.NotNull(result.Value.State);
        Assert.Equal(BootAbi.Cd, result.Value.State!.Value.Target);
        Assert.Equal(BootAbi.ModeUefi, result.Value.State.Value.Mode);
    }

    [Fact]
    public async Task BadCredentials_ProbeFailsWithoutBasicFallback()
    {
        var failure = await Assert.ThrowsAsync<DiscoveryFailure>(() => DiscoveryService.ProbeAsync(Address, new DeviceCredential("fixture-user", "wrong"), certPolicy: Bc.CertSkipAll));
        Assert.Equal(401u, failure.HttpStatus);
    }
}
