using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Avalonia.VisualTree;
using BControl.Core.Localization;
using BControl.Core.Native;
using BControl.Core.Redfish;
using BControl.Desktop.Services;
using BControl.Desktop.ViewModels;
using BControl.Desktop.Views;

namespace BControl.Desktop.Tests;
[Collection("Avalonia UI")]
public sealed class ServerControlTests
{
    private sealed class FakeService : IServerControlService
    {
        public DiscoveryService.ControlSnapshot Snapshot { get; set; } = new(null, null, 0);
        public uint PowerFlags { get; set; } = RedfishAbi.TaskPending;
        public RedfishSession.BootApplyResult? BootResult { get; set; }
        public uint? PowerAction { get; private set; }
        public (uint Target, uint Mode)? BootRequest { get; private set; }

        public Task<DiscoveryService.ControlSnapshot> ReadAsync(ServerRecord record, DeviceCredential credential, CancellationToken cancellation) => Task.FromResult(Snapshot);
        public Task<uint> PowerAsync(ServerRecord record, DeviceCredential credential, uint action, CancellationToken cancellation)
        {
            PowerAction = action;
            return Task.FromResult(PowerFlags);
        }

        public Task<RedfishSession.BootApplyResult?> SetBootOnceAsync(ServerRecord record, DeviceCredential credential, uint target, uint mode, CancellationToken cancellation)
        {
            BootRequest = (target, mode);
            return Task.FromResult(BootResult);
        }
    }

    private static ServerRecord Record(uint protocol = 1) => new()
    {
        ServerId = "server-1",
        Name = "lab",
        Address = "https://bmc.example",
        Protocol = protocol,
        SystemUri = "/redfish/v1/Systems/1",
        CertPolicy = Bc.CertStrict,
    };
    private static ServerControlViewModel Create(FakeService service, ServerRecord? record = null) => new(record ?? Record(), () => Task.FromResult<StoredCredential?>(new StoredCredential("op", "pw")), service);
    private static RedfishSession.BootState Boot(uint flags = BootAbi.Enabled | BootAbi.TargetsKnown | BootAbi.OnceSupported, uint target = BootAbi.Cd, uint mode = BootAbi.ModeUefi, uint targets = (1u << (int)BootAbi.Pxe) | (1u << (int)BootAbi.Cd), uint modes = 2 | 4) => new(target, mode, flags, targets, modes, Bc.Ok);
    [Fact]
    public async Task KvmPowerWindowConfirmsTheClickedActionBeforeSendingIt()
    {
        using var ui = HeadlessUnitTestSession.StartNew(typeof(KvmTestApp));
        await ui.Dispatch(() =>
        {
            var service = new FakeService
            {
                Snapshot = new(new RedfishSession.ResetCapabilities(
                    (1u << (int)RedfishAbi.ResetOn) | (1u << (int)RedfishAbi.ResetForceRestart), "/reset"), Boot(), 0)
            };
            using var model = Create(service);
            var window = new KvmPowerWindow(model);
            window.Show();
            try
            {
                Dispatcher.UIThread.RunJobs();
                var restart = window.GetVisualDescendants().OfType<Button>().Single(button =>
                    button.DataContext is ServerControlViewModel.PowerOption { Action: RedfishAbi.ResetForceRestart });
                restart.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                Assert.Null(service.PowerAction);
                Assert.Single(window.OwnedWindows.OfType<ConfirmDialog>()).Close(false);
                Dispatcher.UIThread.RunJobs();
                Assert.Null(service.PowerAction);

                restart.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                Assert.Single(window.OwnedWindows.OfType<ConfirmDialog>()).Close(true);
                Dispatcher.UIThread.RunJobs();
                Assert.Equal(RedfishAbi.ResetForceRestart, service.PowerAction);
            }
            finally { window.Close(); }

            return true;
        }, CancellationToken.None);
    }

    [Fact]
    public async Task Load_FiltersPowerActionsByAdvertisedMask()
    {
        var service = new FakeService
        {
            Snapshot = new DiscoveryService.ControlSnapshot(new RedfishSession.ResetCapabilities((1u << 0) | (1u << 4), "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset"), Boot(), 0),
        };
        using var model = Create(service);
        await model.LoadAsync();
        Assert.Equal(new uint[] { RedfishAbi.ResetOn, RedfishAbi.ResetForceRestart }, model.PowerActions.Select(item => item.Action));
        Assert.True(model.CanApplyPower);
        Assert.Equal(Loc.F("boot.override", ("mode", Loc.T("boot.nextBoot")), ("target", Loc.T("boot.target.cd"))), model.BootStatus);
        Assert.Contains(model.BootTargets, item => item.Target == BootAbi.Cd);
        Assert.Contains(model.BootModes, item => item.Mode == BootAbi.ModeUefi);
    }

    [Fact]
    public async Task IpmiRecord_UsesInjectedServiceWithoutRequiringSystemUri()
    {
        var service = new FakeService
        {
            Snapshot = new(new RedfishSession.ResetCapabilities(1, ""), null, 0)
        };
        var record = Record(2);
        record.SystemUri = "";
        using var model = Create(service, record);
        await model.LoadAsync();
        Assert.Single(model.PowerActions);
        Assert.True(model.CanApplyPower);
        Assert.Empty(model.BootTargets);
        Assert.Equal("", model.Status);
    }

    [Fact]
    public async Task Power_ConfirmsAndReportsPendingTask()
    {
        var service = new FakeService
        {
            Snapshot = new DiscoveryService.ControlSnapshot(new RedfishSession.ResetCapabilities(1u << (int)RedfishAbi.ResetGracefulShutdown, "/reset"), Boot(), 0),
        };
        using var model = Create(service);
        await model.LoadAsync();
        model.SelectedPower = model.PowerActions.Single();
        var prompted = "";
        await model.ApplyPowerAsync(message =>
        {
            prompted = message;
            return Task.FromResult(true);
        });
        Assert.Equal(Loc.F("power.confirm", ("action", Loc.T("power.action.gracefulShutdown"))), prompted);
        Assert.Equal(RedfishAbi.ResetGracefulShutdown, service.PowerAction);
        Assert.Equal(Loc.T("power.acceptedTask"), model.PowerStatus);
        Assert.True(model.Changed);
    }

    [Fact]
    public async Task Boot_WritesOnlyOnceAndReportsReadBack()
    {
        var state = Boot(target: BootAbi.Cd, mode: BootAbi.ModeUefi);
        var service = new FakeService
        {
            Snapshot = new DiscoveryService.ControlSnapshot(new RedfishSession.ResetCapabilities(0, "/reset"), Boot(), 0),
            BootResult = new RedfishSession.BootApplyResult(RedfishAbi.BootVerified, state),
        };
        using var model = Create(service);
        await model.LoadAsync();
        model.SelectedTarget = model.BootTargets.Single(item => item.Target == BootAbi.Cd);
        model.SelectedMode = model.BootModes.Single(item => item.Mode == BootAbi.ModeUefi);
        await model.ApplyBootAsync(_ => Task.FromResult(true));
        Assert.Equal((BootAbi.Cd, BootAbi.ModeUefi), service.BootRequest);
        Assert.Equal(Loc.T("boot.appliedReadBack"), model.BootStatus);
        Assert.True(model.Changed);
    }

    [Fact]
    public async Task Boot_WithoutOnceAdvertised_CannotApplyOverride()
    {
        var service = new FakeService
        {
            Snapshot = new DiscoveryService.ControlSnapshot(null, Boot(flags: BootAbi.TargetsKnown, target: BootAbi.None), 0),
        };
        using var model = Create(service);
        await model.LoadAsync();
        Assert.False(model.CanApplyBoot);
        Assert.Equal(Loc.T("boot.onceUnsupported"), model.BootStatus);
        Assert.Single(model.BootTargets);
    }
}
