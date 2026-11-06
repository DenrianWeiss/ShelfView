using BControl.Desktop.ViewModels;

namespace BControl.Desktop.Tests;

public sealed class WorkspaceRegistryTests
{
    [Fact]
    public void SameKey_OpensSingleTab()
    {
        var registry = new WorkspaceRegistry();
        var key = new WorkspaceKey("srv-1", WorkspaceFeature.Kvm);
        var first = new WorkspaceTab(key, "KVM", new object());
        var second = new WorkspaceTab(key, "KVM", new object());
        Assert.True(registry.TryAdd(first));
        Assert.False(registry.TryAdd(second));
        Assert.Same(first, registry.Find(key));
    }

    [Fact]
    public void DifferentFeatures_GetDistinctTabs_ForSameServer()
    {
        var registry = new WorkspaceRegistry();
        var kvm = new WorkspaceTab(new WorkspaceKey("srv-1", WorkspaceFeature.Kvm), "KVM", new object());
        var sol = new WorkspaceTab(new WorkspaceKey("srv-1", WorkspaceFeature.Sol), "SOL", new object());
        var media = new WorkspaceTab(new WorkspaceKey("srv-1", WorkspaceFeature.Media), "媒体", new object());
        Assert.True(registry.TryAdd(kvm));
        Assert.True(registry.TryAdd(sol));
        Assert.True(registry.TryAdd(media));
        Assert.Equal(3, registry.Tabs.Count());
    }

    [Fact]
    public void ResourceId_ParticipatesInIdentity()
    {
        var keyA = new WorkspaceKey("srv-1", WorkspaceFeature.Media, "cd");
        var keyB = new WorkspaceKey("srv-1", WorkspaceFeature.Media, "fd");
        Assert.NotEqual(keyA, keyB);
        Assert.Equal(keyA, new WorkspaceKey("srv-1", WorkspaceFeature.Media, "cd"));
    }

    [Fact]
    public void Removal_NotifiesSubscriber()
    {
        var registry = new WorkspaceRegistry();
        WorkspaceTab? removed = null;
        registry.TabRemoved += tab => removed = tab;
        var tab = new WorkspaceTab(new WorkspaceKey("srv-1", WorkspaceFeature.Kvm), "KVM", new object());
        registry.TryAdd(tab);
        Assert.True(registry.TryRemove(tab.Key, out _));
        Assert.Same(tab, removed);
    }
}

public sealed class MediaCloseDecisionTests
{
    [Theory]
    [InlineData(MediaCloseChoice.Cancel, true, false, false, MediaCloseResult.Cancelled)]
    [InlineData(MediaCloseChoice.KeepMounted, true, false, false, MediaCloseResult.KeptMounted)]
    [InlineData(MediaCloseChoice.EjectAndClose, true, true, false, MediaCloseResult.Ejected)]
    [InlineData(MediaCloseChoice.EjectAndClose, true, false, true, MediaCloseResult.EjectUnknown)]
    [InlineData(MediaCloseChoice.EjectAndClose, true, false, false, MediaCloseResult.KeptMounted)]
    [InlineData(MediaCloseChoice.EjectAndClose, false, false, false, MediaCloseResult.Closed)]
    public void Resolve_MapsChoicesHonestly(MediaCloseChoice choice, bool mounted, bool ok, bool unknown, MediaCloseResult expected)
        => Assert.Equal(expected, MediaCloseDecision.Resolve(choice, mounted, ok, unknown));
}
