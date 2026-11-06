using System.Collections.Concurrent;
using BControl.Core;
using BControl.Core.Native;
using BControl.Core.Redfish;
using BControl.Desktop.Services;

namespace BControl.Desktop.Tests;

public sealed class OverviewRefresherTests
{
    [Fact]
    public async Task UnresponsiveCredentialDoesNotHoldRefreshOrStartLateLogin()
    {
        var pending = new TaskCompletionSource<DeviceCredential?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var records = Enumerable.Range(0, 6).Select(i => Record(i.ToString(), "ep-" + i)).ToArray();
        records[0].Timeout = new HostTimeout(1);
        var reads = 0;
        var fetched = new ConcurrentBag<string>();
        var refresher = new OverviewRefresher((record, _, _, _) =>
        {
            fetched.Add(record.ServerId);
            return Task.FromResult(new DeviceOverview(new DiscoveredSystem("", "", "", "", "", Bc.PowerOn, "On"),
                DateTimeOffset.UtcNow, default!, default!, Bc.Ok, 0, Bc.Ok));
        });
        Task<DeviceCredential?> Credential(ServerRecord record, CancellationToken _)
        {
            if (record.ServerId != "0") return Task.FromResult<DeviceCredential?>(new("op", "test"));
            Interlocked.Increment(ref reads);
            return pending.Task;
        }
        try
        {
            await refresher.RefreshAsync(records, Credential, _ => Task.CompletedTask).WaitAsync(TimeSpan.FromSeconds(3));
            await refresher.RefreshAsync(records, Credential, _ => Task.CompletedTask).WaitAsync(TimeSpan.FromSeconds(3));
            Assert.Equal(1, reads);
            Assert.DoesNotContain("0", fetched);
            Assert.Contains("5", fetched);
        }
        finally { pending.TrySetResult(new("op", "test")); }
    }
    private static ServerRecord Record(string id, string endpoint, bool unconfirmed = false) => new()
    {
        ServerId = id, EndpointId = endpoint, Name = id, Username = "op",
        SessionUnconfirmed = unconfirmed,
    };

    private static async Task<Dictionary<string, List<OverviewOutcome>>> CollectAsync(
        IReadOnlyList<ServerRecord> records,
        Func<ServerRecord, CancellationToken, Task<DeviceCredential?>> credentials,
        Func<DeviceCredential, ServerRecord, Task<DeviceOverview>>? fetch = null,
        int credentialDelayMs = 0, int fetchDelayMs = 0,
        Func<OverviewUpdate, Task>? extraUpdate = null)
    {
        var updates = new ConcurrentDictionary<string, List<OverviewOutcome>>();
        OverviewRefresher.FetchDelegate fetchDelegate = async (record, credential, budget, ct) =>
        {
            if (fetch != null) return await fetch(credential, record);
            await Task.Delay(fetchDelayMs, ct);
            return new DeviceOverview(new DiscoveredSystem(record.SystemUri, record.Name, "M", "X", "", Bc.PowerOn, "On"),
                DateTimeOffset.UtcNow, default!, default!, Bc.Ok, 0, Bc.Ok);
        };
        var refresher = new OverviewRefresher(fetchDelegate);
        await refresher.RefreshAsync(records, credentials, update =>
        {
            updates.AddOrUpdate(update.ServerId, _ => new List<OverviewOutcome> { update.Outcome },
                (_, list) => { lock (list) list.Add(update.Outcome); return list; });
            return extraUpdate?.Invoke(update) ?? Task.CompletedTask;
        });
        return updates.ToDictionary(p => p.Key, p => p.Value);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NativeCancellationAtDeviceDeadlineReportsTimeout(bool discoveryFailure)
    {
        var record = Record("slow", "ep-slow");
        record.Timeout = new HostTimeout(1);
        var results = new List<OverviewOutcome>();
        var refresher = new OverviewRefresher(async (_, _, _, cancellation) =>
        {
            try { await Task.Delay(Timeout.Infinite, cancellation); }
            catch (OperationCanceledException) { }
            if (discoveryFailure) throw new DiscoveryFailure(Bc.Cancelled, 0, 4);
            throw new BcException(Bc.Cancelled, "cancelled");
        });
        await refresher.RefreshAsync(new[] { record }, StandardCredentials(), update =>
        {
            results.Add(update.Outcome);
            return Task.CompletedTask;
        });
        var failure = Assert.IsType<OverviewOutcome.Failure>(results.Last());
        Assert.Equal(Bc.Timeout, Assert.IsType<OverviewFailure.Request>(failure.Reason).Status);
        Assert.Equal(discoveryFailure, refresher.IsEndpointUncertain(record.EndpointId));
    }

    [Fact]
    public async Task SlowDevice_DoesNotDelayOtherDeviceResult()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var fastResult = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var refresh = CollectAsync(new[] { Record("slow", "ep-slow"), Record("fast", "ep-fast") },
            StandardCredentials(), async (_, record) =>
            {
                if (record.ServerId == "slow") await release.Task;
                return new DeviceOverview(new DiscoveredSystem("", record.Name, "", "", "", Bc.PowerOn, "On"),
                    DateTimeOffset.UtcNow, default!, default!, Bc.Ok, 0, Bc.Ok);
            }, extraUpdate: update =>
            {
                if (update.ServerId == "fast" && update.Outcome is OverviewOutcome.Value) fastResult.TrySetResult();
                return Task.CompletedTask;
            });
        try
        {
            await fastResult.Task.WaitAsync(TimeSpan.FromSeconds(2));
            Assert.False(refresh.IsCompleted);
        }
        finally { release.TrySetResult(); }
        var outcomes = await refresh;
        Assert.All(outcomes, item => Assert.Contains(item.Value, value => value is OverviewOutcome.Value));
    }

    [Fact]
    public async Task SameEndpoint_IsSerialized()
    {
        var records = Enumerable.Range(0, 4).Select(i => Record("s" + i, "ep-shared")).ToList();
        var active = 0;
        var maxActive = 0;
        var updates = await CollectAsync(records, StandardCredentials(), async (_, record) =>
        {
            var now = Interlocked.Increment(ref active);
            maxActive = Math.Max(maxActive, now);
            await Task.Delay(50);
            Interlocked.Decrement(ref active);
            return new DeviceOverview(new DiscoveredSystem("", record.Name, "", "", "", Bc.PowerOn, "On"),
                DateTimeOffset.UtcNow, default!, default!, Bc.Ok, 0, Bc.Ok);
        });
        Assert.Equal(1, maxActive);
        Assert.All(updates, u => Assert.Contains(u.Value, o => o is OverviewOutcome.Value));
    }

    [Fact]
    public async Task DifferentEndpoints_RunInParallel_UpToFour()
    {
        var records = Enumerable.Range(0, 6).Select(i => Record("s" + i, "ep" + i)).ToList();
        var active = 0;
        var maxActive = 0;
        await CollectAsync(records, StandardCredentials(), async (_, _) =>
        {
            var now = Interlocked.Increment(ref active);
            maxActive = Math.Max(maxActive, now);
            await Task.Delay(80);
            Interlocked.Decrement(ref active);
            return new DeviceOverview(new DiscoveredSystem("", "", "", "", "", Bc.PowerOn, "On"),
                DateTimeOffset.UtcNow, default!, default!, Bc.Ok, 0, Bc.Ok);
        });
        Assert.True(maxActive >= 2, $"应至少 2 并发，实际 {maxActive}");
        Assert.True(maxActive <= 4, $"不应超过 4 并发，实际 {maxActive}");
    }

    [Fact]
    public async Task RunningRefresh_IsNotStacked()
    {
        var records = new List<ServerRecord> { Record("s0", "ep0") };
        var updates = new List<OverviewUpdate>();
        OverviewRefresher.FetchDelegate fetch = async (_, _, _, ct) =>
        {
            await Task.Delay(200, ct);
            return new DeviceOverview(new DiscoveredSystem("", "", "", "", "", Bc.PowerOn, "On"),
                DateTimeOffset.UtcNow, default!, default!, Bc.Ok, 0, Bc.Ok);
        };
        var refresher = new OverviewRefresher(fetch);
        var first = refresher.RefreshAsync(records, StandardCredentials(), u =>
        {
            lock (updates) updates.Add(u);
            return Task.CompletedTask;
        });
        var second = await refresher.RefreshAsync(records, StandardCredentials(), _ => Task.CompletedTask);
        Assert.False(second);
        await first;
    }

    [Fact]
    public async Task UnconfirmedEndpoint_IsQuarantined_AndReportsSessionUnconfirmed()
    {
        var record = Record("s0", "ep0");
        var updates = await CollectAsync(new[] { record }, StandardCredentials(),
            (_, _) => Task.FromResult(new DeviceOverview(
                new DiscoveredSystem("", "", "", "", "", Bc.PowerOn, "On"),
                DateTimeOffset.UtcNow, default!, default!, Bc.Ok, 0, Bc.IoError)));
        var outcomes = updates["s0"];
        Assert.Contains(outcomes, o => o is OverviewOutcome.Failure f && f.Reason is OverviewFailure.SessionUnconfirmed);
    }

    [Fact]
    public async Task MissingCredentials_ReportFailure()
    {
        var record = Record("s0", "ep0");
        var updates = await CollectAsync(new[] { record },
            (_, _) => Task.FromResult<DeviceCredential?>(null));
        Assert.Contains(updates["s0"], o => o is OverviewOutcome.Failure f && f.Reason is OverviewFailure.CredentialsUnavailable);
    }

    private static Func<ServerRecord, CancellationToken, Task<DeviceCredential?>> StandardCredentials()
        => (_, _) => Task.FromResult<DeviceCredential?>(new DeviceCredential("op", "pw"));
}
