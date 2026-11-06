using System.Runtime.InteropServices;
using BControl.Core.Kvm;
using BControl.Core.Native;

namespace BControl.Core.Tests;
public sealed class ConsoleRecoveryTests
{
    private static BcServiceProfile Profile => new()
    {
        StructSize = 20,
        Service = 1,
        Family = 2,
        Variant = 1,
        Evidence = 2
    };

    private static Exception Expired(bool cleaned)
    {
        var error = new IOException("expired fixture ticket");
        error.Data[ConsoleAttempt.Key] = new ConsoleAttempt(Profile, new() { StructSize = (uint)Marshal.SizeOf<BcConsoleFailure>(), Status = Bc.AuthenticationFailed, Phase = 5, Cause = 4, Service = 1, Family = 2, Profile = 1 }, cleaned);
        return error;
    }

    [Theory]
    [InlineData(2u, 1u, true)]
    [InlineData(5u, 3u, false)]
    [InlineData(2u, 2u, false)]
    public void OnlyExplicitCredentialCauseRequestsNewCredentials(uint phase, uint cause, bool credentialFailure)
    {
        var failure = new ConsoleFailureException(new() { Status = Bc.AuthenticationFailed, Phase = phase, Cause = cause });
        Assert.Equal(credentialFailure, failure.IsCredentialFailure);
    }

    [Fact]
    public async Task AlreadyCancelledStartupDoesNotOpenAClient()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => NativeConsoleClient.ConnectAsync(
            new ConsoleConnectionOptions("https://bmc.invalid", Cancellation: cancellation.Token), new("fixture", "fixture")));
    }

    [Fact]
    public async Task ExpiredTicketRefreshIsBoundedAcrossAttempts()
    {
        var attempts = 0;
        await Assert.ThrowsAsync<IOException>(() => RecoveringConsoleSession.ConnectAsync(() =>
        {
            attempts++;
            throw Expired(true);
        }, () => false));
        Assert.Equal(2, attempts);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task UnconfirmedCleanupOrDependentMediaStopsRefresh(bool cleaned, bool mediaActive)
    {
        var attempts = 0;
        await Assert.ThrowsAsync<IOException>(() => RecoveringConsoleSession.ConnectAsync(() =>
        {
            attempts++;
            throw Expired(cleaned);
        }, () => mediaActive));
        Assert.Equal(1, attempts);
    }
}
