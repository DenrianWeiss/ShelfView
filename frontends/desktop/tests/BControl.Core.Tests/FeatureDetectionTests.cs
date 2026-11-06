using BControl.Core.Native;

namespace BControl.Core.Tests;

public sealed class FeatureDetectionTests
{
    [Theory]
    [InlineData(DetectionEvidence.None, Bc.Ok, DetectionState.Unknown, false)]
    [InlineData(DetectionEvidence.Hint, Bc.Ok, DetectionState.Unknown, false)]
    [InlineData(DetectionEvidence.Descriptor, Bc.Ok, DetectionState.Attemptable, true)]
    [InlineData(DetectionEvidence.Handshake, Bc.Ok, DetectionState.Verified, true)]
    [InlineData(DetectionEvidence.Handshake, Bc.Timeout, DetectionState.Failed, false)]
    [InlineData(DetectionEvidence.None, Bc.Unsupported, DetectionState.Unsupported, false)]
    public void NativeClassificationPreservesEvidenceAndCleanup(DetectionEvidence evidence, uint status,
        DetectionState state, bool canAttempt)
    {
        var result = FeatureDetection.FromProbe(DeviceFeature.Kvm, evidence, status, Bc.IoError);
        Assert.Equal(DeviceFeature.Kvm, result.Feature);
        Assert.Equal(state, result.State);
        Assert.Equal(evidence, result.Evidence);
        Assert.Equal(status, result.Status);
        Assert.Equal(Bc.IoError, result.CleanupStatus);
        Assert.Equal(canAttempt, result.CanAttempt);
    }
}
