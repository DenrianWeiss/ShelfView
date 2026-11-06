using BControl.Core.Redfish;

namespace BControl.Desktop.ViewModels;

public sealed class MediaDeviceRowViewModel(VirtualMediaDevice device) : ViewModelBase
{
    public VirtualMediaDevice Device { get; private set; } = device;
    public string Uri => Device.Uri;
    public string Name => Device.Name;
    public string DisplayImage => Device.DisplayImage;
    public bool Inserted => Device.Inserted;
    public bool CanInsert => Device.CanInsert;
    public bool CanEject => Device.CanEject;
    public bool SourceUnverified => Device.SourceUnverified;
    public bool SourceMismatch => Device.SourceMismatch;
    private string _imageUrl = "";
    public string ImageUrl { get => _imageUrl; set => SetProperty(ref _imageUrl, value); }
    public void Update(VirtualMediaDevice value)
    {
        Device = value;
        foreach (var property in new[] { nameof(Device), nameof(Name), nameof(DisplayImage), nameof(Inserted),
            nameof(CanInsert), nameof(CanEject), nameof(SourceUnverified), nameof(SourceMismatch) }) RaiseChanged(property);
    }
}
