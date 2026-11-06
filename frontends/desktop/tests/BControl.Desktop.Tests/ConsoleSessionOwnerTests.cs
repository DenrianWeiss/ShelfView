using BControl.Core.Kvm;
using BControl.Core.Media;
using BControl.Desktop.Services;

namespace BControl.Desktop.Tests;
public sealed class ConsoleSessionOwnerTests
{
    private sealed class Recovery : IMediaRecoveryStore
    {
        public bool Pending;
        public bool FailBegin;
        public int Clears;
        public Task<bool> ReadPendingAsync(CancellationToken cancellation = default) => Task.FromResult(Pending);
        public Task BeginAsync(CancellationToken cancellation = default)
        {
            if (FailBegin) { Pending = true; throw new IOException("fixture competing owner"); }
            Pending = true; return Task.CompletedTask;
        }
        public Task ClearAsync(CancellationToken cancellation = default) { ++Clears; Pending = false; return Task.CompletedTask; }
        public Task<IMediaRecoveryObservation> ObserveAsync(CancellationToken cancellation = default) => Task.FromResult<IMediaRecoveryObservation>(new Observation(this));
        private sealed class Observation(Recovery owner) : IMediaRecoveryObservation
        {
            public BControl.Core.Storage.MediaRecoveryState State { get; } = new(true, owner.Pending);
            public Task ClearAsync(CancellationToken cancellation = default) => owner.ClearAsync(cancellation);
            public void Dispose() { }
        }
    }
    [Fact]
    public async Task FailedRecoveryFenceNeverMountsOrClearsAnotherPendingMarker()
    {
        var recovery = new Recovery { FailBegin = true }; var calls = 0;
        await using var owner = new ConsoleSessionOwner(_ => { ++calls; return Task.FromResult<IKvmSession>(new Console()); }, recovery: recovery);
        await Assert.ThrowsAsync<IOException>(() => owner.MountAsync("fixture.iso"));
        Assert.Equal(0, calls); Assert.Equal(0, recovery.Clears);
        Assert.True(recovery.Pending); Assert.True(owner.CleanupPending);
    }
    [Fact]
    public async Task RestoredUnknownMediaRequiresVerifiedRemovalBeforeReplacement()
    {
        var recovery = new Recovery { Pending = true }; var calls = 0;
        await using var owner = new ConsoleSessionOwner(_ => { ++calls; return Task.FromResult<IKvmSession>(new Console()); }, recovery: recovery);
        await owner.RestoreAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => owner.AcquireAsync());
        await Assert.ThrowsAsync<InvalidOperationException>(() => owner.MountAsync("fixture.iso"));
        Assert.Equal(0, calls);
        await owner.VerifyRecoveryAsync(_ => Task.FromResult(false)); Assert.True(recovery.Pending);
        await owner.VerifyRecoveryAsync(_ => Task.FromResult(true)); Assert.False(recovery.Pending);
        await owner.MountAsync("fixture.iso"); Assert.True(recovery.Pending);
        await owner.VerifyRecoveryAsync(_ => Task.FromResult(true)); Assert.True(recovery.Pending);
        Assert.True(await owner.EjectAsync()); Assert.False(recovery.Pending);
    }
    [Fact]
    public async Task CancelledStartupReleasesGateAndAllowsAnotherAcquire()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var attempts = 0;
        var console = new Console();
        await using var owner = new ConsoleSessionOwner(async cancellation => {
            if (++attempts == 1) {
                started.SetResult();
                await Task.Delay(Timeout.Infinite, cancellation);
            }
            return console;
        });
        using var cancellation = new CancellationTokenSource();
        var first = owner.AcquireAsync(cancellation.Token);
        await started.Task;
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        Assert.Same(console, await owner.AcquireAsync());
        await owner.ReleaseAsync();
        Assert.True(console.Disposed);
    }

    [Fact]
    public async Task MediaWorkspaceRefreshesStatisticsWithoutWarningDuringActiveMount()
    {
        var directory = Path.Combine(Path.GetTempPath(), "bcontrol-media-view-" + Guid.NewGuid().ToString("N"));
        await using var vault = await TestVault.CreateAsync(directory);
        var record = new ServerRecord { ServerId = "fixture", Address = "https://fixture.invalid", Username = "fixture" };
        try
        {
            var media = new Media { RemovalUnconfirmed = true, Statistics = (1, 2048) };
            await using var owner = new ConsoleSessionOwner(() => throw new InvalidOperationException(), _ => Task.FromResult<ILocalMediaSession?>(media));
            await owner.MountAsync("fixture.iso");
            await using var model = new BControl.Desktop.ViewModels.MediaWorkspaceViewModel(record, () => Task.FromResult<StoredCredential?>(null), vault.Store.RemoteMediaFor(record), owner);
            Assert.False(model.CleanupPending);
            var before = model.LocalStatistics;
            var changed = new List<string?>();
            model.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
            media.Statistics = (2, 4096);
            model.RefreshLocal();
            Assert.NotEqual(before, model.LocalStatistics);
            Assert.Contains(nameof(model.LocalStatistics), changed);
            await media.DisposeAsync();
            model.RefreshLocal();
            Assert.True(model.CleanupPending);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public async Task IndependentMediaAllowsViewerOpenCloseWithoutSharingItsLifetime()
    {
        var console = new Console();
        var media = new Media();
        await using var owner = new ConsoleSessionOwner(() => Task.FromResult<IKvmSession>(console), _ => Task.FromResult<ILocalMediaSession?>(media));
        await owner.MountAsync("fixture.iso");
        Assert.False(owner.HasDependentMedia);
        await owner.AcquireAsync();
        await owner.ReleaseAsync();
        Assert.True(console.Disposed);
        Assert.False(media.Disposed);
        Assert.True(owner.HasMedia);
        await owner.EjectAsync();
    }

    [Fact]
    public async Task ViewerDetachReleasesHeldInputWhileMediaKeepsSessionAlive()
    {
        var console = new Console();
        await using var owner = new ConsoleSessionOwner(() => Task.FromResult<IKvmSession>(console));
        await using var viewer = new BControl.Desktop.ViewModels.KvmWorkspaceViewModel(new ServerRecord(), () => Task.FromResult<StoredCredential?>(new("fixture", "fixture")), owner);
        await viewer.ConnectAsync();
        await owner.MountAsync("fixture.iso");
        await viewer.SendKeyAsync(1, 0xffe3);
        await viewer.SendPointerAsync(1, 10, 20);
        await viewer.DisconnectAsync();
        Assert.False(console.Disposed);
        Assert.Contains((0, 0xffe3u), console.Keys);
        Assert.Equal((byte)0, console.Buttons);
        await owner.EjectAsync();
    }

    [Fact]
    public async Task ClosingViewerPreservesMediaUntilConfirmedEjection()
    {
        var console = new Console();
        await using var owner = new ConsoleSessionOwner(() => Task.FromResult<IKvmSession>(console));
        await owner.AcquireAsync();
        await owner.MountAsync("fixture.iso");
        await owner.ReleaseAsync();
        Assert.False(console.Disposed);
        Assert.Same(console, await owner.AcquireAsync());
        await owner.ReleaseAsync();
        Assert.True(await owner.EjectAsync());
        Assert.False(owner.HasMedia);
        Assert.True(console.Disposed);
    }

    [Fact]
    public async Task FailedMountRetainsUnknownRemovalAndBlocksReplacement()
    {
        var media = new Media
        {
            RemovalUnconfirmed = true
        };
        var console = new Console
        {
            Failure = new MediaStartupException(media, new IOException("fixture"))
        };
        await using var owner = new ConsoleSessionOwner(() => Task.FromResult<IKvmSession>(console));
        await Assert.ThrowsAsync<MediaStartupException>(() => owner.MountAsync("fixture.iso"));
        Assert.True(owner.CleanupPending);
        Assert.False(console.Disposed);
        await Assert.ThrowsAsync<InvalidOperationException>(() => owner.MountAsync("next.iso"));
        await owner.ConfirmCleanupAsync();
        Assert.False(owner.HasMedia);
        Assert.True(console.Disposed);
    }

    [Fact]
    public async Task IndependentMediaDoesNotAcquireViewer()
    {
        var media = new Media();
        await using var owner = new ConsoleSessionOwner(() => throw new InvalidOperationException(), _ => Task.FromResult<ILocalMediaSession?>(media));
        await owner.MountAsync("fixture.iso");
        Assert.True(await owner.EjectAsync());
        Assert.True(media.Disposed);
    }

    private sealed class Media : ILocalMediaSession
    {
        public string Name => "fixture.iso";
        public (ulong Requests, ulong Bytes)? Statistics { get; set; }
        public bool IsActive => !Disposed;
        public bool RemovalUnconfirmed { get; set; }
        public string? Error => null;

        public bool Disposed;
        public async Task<bool> EjectAsync()
        {
            await DisposeAsync();
            return !RemovalUnconfirmed;
        }

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class Console : IKvmSession, ILocalMediaConsole
    {
        public bool Disposed;
        public List<(int Down, uint Key)> Keys = new();
        public byte Buttons;
        public Exception? Failure;
        public bool IsConnected => !Disposed;
        public bool LocalMediaAvailable => true;
        public KvmFrame? LatestFrame => null;

        public event Action<KvmFrame>? FrameReceived
        {
            add
            {
            }

            remove
            {
            }
        }

        public event Action<string>? Failed
        {
            add
            {
            }

            remove
            {
            }
        }

        public event Action? Closed
        {
            add
            {
            }

            remove
            {
            }
        }

        public Task SendKeyAsync(int down, uint keysym)
        {
            Keys.Add((down, keysym));
            return Task.CompletedTask;
        }

        public Task SendPointerAsync(byte buttons, ushort x, ushort y)
        {
            Buttons = buttons;
            return Task.CompletedTask;
        }

        public Task<ILocalMediaSession> MountIsoAsync(string path) => Failure == null ? Task.FromResult<ILocalMediaSession>(new Media()) : Task.FromException<ILocalMediaSession>(Failure);
        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
        }
    }
}
