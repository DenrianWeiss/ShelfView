using BControl.Core.Localization;
using BControl.Core.Native;
using BControl.Desktop.Services;
using BControl.Desktop.ViewModels;

namespace BControl.Desktop.Tests;

public sealed class ServerRowTests
{
    [Fact]
    public void FailureRetainsCachedReadingsAndWarningAfterLanguageRefresh()
    {
        var cached = new CachedOverview
        {
            ObservedAt = DateTimeOffset.UtcNow.AddMinutes(-5),
            Manufacturer = "Fixture", Model = "Server", PowerState = Bc.PowerOn,
            CpuCelsius = 42, NormalCelsius = 45,
        };
        var row = new ServerRowViewModel(new ServerRecord { LastOverview = cached });
        row.RenderCached(cached);
        var power = row.Power;
        var temperature = row.CpuTemperature;
        row.ApplyOutcome(new OverviewOutcome.Failure(new OverviewFailure.CredentialsUnavailable()));
        Assert.True(row.HasConnectionFailure);
        Assert.True(row.Expired);
        Assert.Equal(power, row.Power);
        Assert.Equal(temperature, row.CpuTemperature);
        row.RefreshLanguage();
        Assert.Equal(Loc.T("overview.credentialsUnavailable"), row.Connectivity);
        Assert.True(row.HasConnectionFailure);
    }

    [Fact]
    public void UnreadServerDoesNotDisplayZeroTemperatureOrOfflinePower()
    {
        var row = new ServerRowViewModel(new ServerRecord());
        Assert.Equal(Loc.T("common.unknown"), row.CpuTemperature);
        Assert.Equal(Loc.T("common.unknown"), row.NormalMaximum);
        Assert.Equal(Loc.T("power.state.unknown"), row.Power);
        row.ApplyOutcome(new OverviewOutcome.Failure(new OverviewFailure.Unsupported()));
        Assert.False(row.Expired);
        Assert.True(row.HasConnectionFailure);
        Assert.Equal(Loc.T("power.state.unknown"), row.Power);
    }
}
