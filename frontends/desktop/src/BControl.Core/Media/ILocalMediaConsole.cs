namespace BControl.Core.Media;
public interface ILocalMediaConsole
{
    bool LocalMediaAvailable { get; }
    FeatureDetection LocalMediaDetection => FeatureDetection.FromProbe(DeviceFeature.LocalMedia,
        LocalMediaAvailable ? DetectionEvidence.Descriptor : DetectionEvidence.None);

    Task<ILocalMediaSession> MountIsoAsync(string path);
}
