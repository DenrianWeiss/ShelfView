using System.Runtime.InteropServices;
using BControl.Core.Native;

namespace BControl.Core.Tests;
public sealed class ManagementAbiTests
{
    [Fact]
    public void IpmiLayoutsMatchPortableCHeaders()
    {
        Assert.Equal(4408, Marshal.SizeOf<BcRedfishTaskReference>());
        Assert.Equal(128, Marshal.SizeOf<BcIpmiSensorRecord>());
        Assert.Equal(232, Marshal.SizeOf<BcIpmiSensorDescriptor>());
        Assert.Equal(59416, Marshal.SizeOf<BcIpmiSensorCatalog>());
        Assert.Equal(36, Marshal.SizeOf<BcIpmiBootInfo>());
        Assert.Equal(96, Marshal.SizeOf<BcIpmiBootResult>());
        Assert.Equal(20, Marshal.SizeOf<BcIpmiChassisCapabilities>());
        Assert.Equal(8260, Marshal.SizeOf<BcIpmiFruInfo>());
        Assert.Equal(164, Marshal.SizeOf<BcIpmiFruInventory>());
        Assert.Equal(21572, Marshal.SizeOf<BcIpmiLanConfig>());
        Assert.Equal(5176, Marshal.SizeOf<BcIpmiSelLog>());
        if (IntPtr.Size == 8)
        {
            Assert.Equal(128, Marshal.SizeOf<BcRedfishTaskInfo>());
            Assert.Equal(168, Marshal.SizeOf<ConsoleClientOptions>());
            Assert.Equal(88, Marshal.SizeOf<ConsoleClientInfo>());
            Assert.Equal(88, Marshal.SizeOf<ConsoleClientChoice>());
            Assert.Equal(144, Marshal.OffsetOf<ConsoleClientOptions>(nameof(ConsoleClientOptions.Preferred)).ToInt32());
            Assert.Equal(76, Marshal.SizeOf<BcHuaweiVmmInfo>());
            Assert.Equal(72, Marshal.SizeOf<MediaOptions>());
            Assert.Equal(56, Marshal.SizeOf<MediaSessionInfo>());
            Assert.Equal(32, Marshal.SizeOf<BcMediaSource>());
            Assert.Equal(80, Marshal.SizeOf<BcIdracLaunchUri>());
            Assert.Equal(524, Marshal.SizeOf<BcIdracLaunch>());
            Assert.Equal(44, Marshal.SizeOf<BcRecoveryView>());
            Assert.Equal(272, Marshal.SizeOf<BcSensorDetails>());
            Assert.Equal(56, Marshal.SizeOf<BcWebEntryOptions>());
            Assert.Equal(80, Marshal.SizeOf<BcWebSessionOptions>());
            Assert.Equal(56, Marshal.SizeOf<BcJviewerArtifactOptions>());
            Assert.Equal(96, Marshal.SizeOf<BcHuaweiLaunchOptions>());
            Assert.Equal(64, Marshal.SizeOf<BcHuaweiLaunchResult>());
            Assert.Equal(1140, Marshal.OffsetOf<BcConsoleDiscoveryPrefix>(nameof(BcConsoleDiscoveryPrefix.Huawei)).ToInt32());
        }
    }
}
