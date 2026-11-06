using System.Runtime.InteropServices;
using BControl.Core.Native;

namespace BControl.Core;

public enum DeviceFeature : uint { Kvm = 1, LocalMedia, RemoteMedia, Serial, Temperature, Power }
public enum DetectionState : uint { Unknown, Attemptable, Verified, Unsupported, Failed }
[Flags]
public enum DetectionEvidence : uint { None = 0, Hint = 1, Descriptor = 2, Handshake = 4, Manual = 8 }

public sealed record FeatureDetection
{
    public DeviceFeature Feature { get; }
    public DetectionState State { get; }
    public DetectionEvidence Evidence { get; }
    public uint Status { get; }
    public uint CleanupStatus { get; }
    public bool CanAttempt => State is DetectionState.Attemptable or DetectionState.Verified;

    internal FeatureDetection(Result result)
    {
        Feature = (DeviceFeature)result.Feature;
        State = (DetectionState)result.State;
        Evidence = (DetectionEvidence)result.Evidence;
        Status = result.Status;
        CleanupStatus = result.CleanupStatus;
    }

    public static FeatureDetection FromProbe(DeviceFeature feature, DetectionEvidence evidence = DetectionEvidence.None,
        uint status = Bc.Ok, uint cleanupStatus = Bc.Ok)
    {
        var result = new Result { StructSize = (uint)Marshal.SizeOf<Result>() };
        Bc.Check(bc_detection_result_set(ref result, (uint)feature, (uint)evidence, status, cleanupStatus), "core.probeCapabilities");
        return new(result);
    }

    internal static FeatureDetection FromProfile(BcServiceProfile profile, uint service)
    {
        var result = new Result { StructSize = (uint)Marshal.SizeOf<Result>() };
        Bc.Check(bc_service_profile_detection(ref profile, service, ref result), "core.probeCapabilities");
        return new(result);
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Result
    {
        public uint StructSize, Feature, State, Evidence, Status, CleanupStatus;
    }
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_detection_result_set(ref Result result, uint feature, uint evidence, uint status, uint cleanup);
    [DllImport(NativeLibs.Bcontrol, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint bc_service_profile_detection(ref BcServiceProfile profile, uint service, ref Result result);
}
