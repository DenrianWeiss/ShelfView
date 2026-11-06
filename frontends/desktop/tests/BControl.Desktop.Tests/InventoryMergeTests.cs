using BControl.Core.Inventory;
using BControl.Desktop.Services;

namespace BControl.Desktop.Tests;
public sealed class InventoryMergeTests
{
    [Fact]
    public void DuplicateUpdatesOnlyNameAndKeepsCredentialAndIdentity()
    {
        var record = new ServerRecord
        {
            ServerId = "s",
            EndpointId = "e",
            Name = "old",
            Address = "https://bmc",
            Username = "owner",
            CredentialRef = "secret-ref",
            Verified = true
        };
        var entries = new[]
        {
            new InventoryEntry(0, 2, uint.MaxValue, "new", record.Address, "other", "")
        };
        var skipped = InventoryMerge.Apply(new[] { record }, entries, false).Single();
        Assert.Equal("old", skipped.Name);
        var merged = InventoryMerge.Apply(new[] { record }, entries, true).Single();
        Assert.Equal("new", merged.Name);
        Assert.Equal("s", merged.ServerId);
        Assert.Equal("secret-ref", merged.CredentialRef);
        Assert.Equal("owner", merged.Username);
        Assert.True(merged.Verified);
        Assert.Equal("old", record.Name);
    }

    [Fact]
    public void SystemsOnOneEndpointShareIdentityAndImportRemainsUnverified()
    {
        var entries = new[]
        {
            new InventoryEntry(0, 1, uint.MaxValue, "a", "https://bmc", "admin", "/Systems/A"),
            new InventoryEntry(1, 1, uint.MaxValue, "b", "https://bmc", "admin", "/Systems/B")
        };
        var merged = InventoryMerge.Apply(Array.Empty<ServerRecord>(), entries, false);
        Assert.Equal(2, merged.Count);
        Assert.Equal(merged[0].EndpointId, merged[1].EndpointId);
        Assert.NotEqual(merged[0].ServerId, merged[1].ServerId);
        Assert.All(merged, record =>
        {
            Assert.False(record.Verified);
            Assert.Empty(record.CredentialRef);
        });
    }
}
