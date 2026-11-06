namespace BControl.Core.Kvm;
public interface IKvmSession : IAsyncDisposable
{
    event Action<KvmFrame>? FrameReceived;
    event Action<string>? Failed;
    event Action? Closed;
    KvmFrame? LatestFrame { get; }

    bool IsConnected { get; }

    FeatureDetection KvmDetection => this is IConsoleProtocol protocol
        ? FeatureDetection.FromProfile(protocol.Profile, 1)
        : FeatureDetection.FromProbe(DeviceFeature.Kvm,
            IsConnected ? DetectionEvidence.Handshake : DetectionEvidence.None);

    Task SendInputAsync(KvmInputEvent input) => input switch {
        KvmInputEvent.Key key => SendKeyAsync(key.Down, key.Keysym),
        KvmInputEvent.Pointer pointer => SendPointerAsync(pointer.Buttons, pointer.X, pointer.Y),
        KvmInputEvent.Scroll scroll => SendScrollAsync(scroll.Buttons, scroll.X, scroll.Y, scroll.Wheel),
        KvmInputEvent.Chord chord => SendChordAsync(chord.Keys),
        _ => throw new ArgumentException(nameof(input))
    };
    Task SendKeyAsync(int down, uint keysym);
    async Task SendChordAsync(IReadOnlyList<uint> keys)
    {
        var copy = Native.ConsoleNative.CopyChord(keys);
        var pressed = new List<uint>();
        Exception? failure = null;
        try { foreach (var key in copy) { pressed.Add(key); await SendKeyAsync(1, key); } }
        catch (Exception error) { failure = error; }
        foreach (var key in pressed.AsEnumerable().Reverse())
            try { await SendKeyAsync(0, key); } catch (Exception error) { failure ??= error; }
        if (failure != null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
    }
    // HID button order: left 1, right 2, middle 4.
    Task SendPointerAsync(byte buttons, ushort x, ushort y);
    bool SupportsScroll => false;
    Task SendScrollAsync(byte buttons, ushort x, ushort y, sbyte wheel) =>
        Task.FromException(new NotSupportedException("Scrolling is unavailable"));
}
