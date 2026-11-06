using BControl.Core.Media;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Input;
using Avalonia.Input.Raw;
using Avalonia.Media;
using Avalonia.Threading;
using BControl.Core.Kvm;
using BControl.Desktop.Services;
using BControl.Desktop.ViewModels;
using BControl.Desktop.Views;


namespace BControl.Desktop.Tests;

public sealed class KvmTestApp : Application
{
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<KvmTestApp>()
        .UseSkia().UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false });
    public override void Initialize()
    {
        Styles.Add(new Avalonia.Themes.Fluent.FluentTheme());
        Styles.Add(new Avalonia.Markup.Xaml.Styling.StyleInclude(new Uri("avares://Iciclecreek.Avalonia.Terminal/"))
        {
            Source = new Uri("avares://Iciclecreek.Avalonia.Terminal/Themes/Generic.axaml")
        });
    }
}

[Collection("Avalonia UI")]
public sealed class KvmViewTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task ConnectionProgressEndsOnSuccessOrFailure(bool fail) => Run(async () =>
    {
        var pending = new TaskCompletionSource<IKvmSession>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var owner = new ConsoleSessionOwner(() => pending.Task);
        await using var model = new KvmWorkspaceViewModel(new ServerRecord(), () => Task.FromResult<StoredCredential?>(new("fixture", "fixture")), owner);
        var view = new KvmWorkspaceView { DataContext = model };
        var window = new Window { Width = 800, Height = 600, Content = view };
        window.Show();
        try
        {
            var connecting = model.ConnectAsync();
            Dispatcher.UIThread.RunJobs();
            var progress = view.FindControl<StackPanel>("ConnectionProgress")!;
            Assert.True(progress.IsVisible);
            Assert.True(((ProgressBar)progress.Children[0]).IsIndeterminate);
            Assert.False(model.CanConnect);
            if (fail) pending.SetException(new IOException("fixture connection failed"));
            else pending.SetResult(new RecordingConsole());
            await connecting;
            Dispatcher.UIThread.RunJobs();
            Assert.False(progress.IsVisible);
            Assert.Equal(!fail, model.IsConnected);
        }
        finally { pending.TrySetCanceled(); window.Close(); }
    });

    [Fact]
    public Task ViewportForwardsHoverClickKeyboardAndReleasesOnFocusLoss() => Run(async () =>
    {
        var session = new RecordingConsole();
        await using var owner = new ConsoleSessionOwner(() => Task.FromResult<IKvmSession>(session));
        await using var model = new KvmWorkspaceViewModel(new ServerRecord(), () => Task.FromResult<StoredCredential?>(new("fixture", "fixture")), owner);
        await model.ConnectAsync();
        var view = new KvmWorkspaceView { DataContext = model };
        var window = new Window { Width = 800, Height = 600, Content = view };
        window.Show();
        try
        {
            Dispatcher.UIThread.RunJobs();
            var viewport = view.FindControl<Border>("Viewport")!;
            var center = viewport.TranslatePoint(new Point(viewport.Bounds.Width / 2, viewport.Bounds.Height / 2), window)!.Value;
            window.MouseMove(center);
            await WaitFor(() => session.Pointers.Contains((0, 2, 1)));
            Assert.Contains(session.Pointers, p => p == (0, 2, 1));
            window.MouseDown(center, MouseButton.Left);
            Assert.True(viewport.IsFocused);
            window.KeyPress(Key.A, RawInputModifiers.None, PhysicalKey.None, null);
            window.KeyRelease(Key.A, RawInputModifiers.None, PhysicalKey.None, null);
            window.KeyPress(Key.Tab, RawInputModifiers.None, PhysicalKey.None, null);
            Assert.True(viewport.IsFocused);
            window.KeyRelease(Key.Tab, RawInputModifiers.None, PhysicalKey.None, null);
            await WaitFor(() => session.Keys.Contains((1, 0xff09u)));
            Assert.Contains((1, (uint)'a'), session.Keys);
            Assert.Contains((0, (uint)'a'), session.Keys);
            Assert.Contains((1, 0xff09u), session.Keys);
            window.MouseUp(new Point(1, 1), MouseButton.Left);
            await WaitFor(() => session.Pointers[^1].Buttons == 0);
            Assert.Equal((byte)0, session.Pointers[^1].Buttons);
            window.KeyPress(Key.LeftCtrl, RawInputModifiers.None, PhysicalKey.None, null);
            window.Focusable = true;
            window.Focus();
            await WaitFor(() => session.Keys.Contains((0, 0xffe3u)));
            Assert.Contains((0, 0xffe3u), session.Keys);
        }
        finally { window.Close(); }
    });

    [Fact]
    public Task NewFrameRepaintsWithoutResizingOrChangingSource() => Run(async () =>
    {
        var session = new RecordingConsole();
        await using var owner = new ConsoleSessionOwner(() => Task.FromResult<IKvmSession>(session));
        await using var model = new KvmWorkspaceViewModel(new ServerRecord(), () => Task.FromResult<StoredCredential?>(new("fixture", "fixture")), owner);
        await model.ConnectAsync();
        var view = new KvmWorkspaceView { DataContext = model };
        var window = new Window { Width = 800, Height = 600, Content = view };
        window.Show();
        try
        {
            Dispatcher.UIThread.RunJobs();
            using var before = window.CaptureRenderedFrame();
            var source = view.FindControl<Image>("Screen")!.Source;
            model.Frame = RecordingConsole.Frame(0, 255, 0);
            Dispatcher.UIThread.RunJobs();
            using var after = window.CaptureRenderedFrame();
            Assert.Same(source, view.FindControl<Image>("Screen")!.Source);
            using var first = new MemoryStream();
            using var second = new MemoryStream();
            before!.Save(first);
            after!.Save(second);
            Assert.False(first.ToArray().SequenceEqual(second.ToArray()));
        }
        finally { window.Close(); }
    });

    [Fact]
    public Task InputAndCleanupFailuresStayInsideWorkspace() => Run(async () =>
    {
        var session = new RecordingConsole();
        await using var owner = new ConsoleSessionOwner(() => Task.FromResult<IKvmSession>(session));
        await using var model = new KvmWorkspaceViewModel(new ServerRecord(), () => Task.FromResult<StoredCredential?>(new("fixture", "fixture")), owner);
        Assert.False(model.ShowDiagnostics);
        await model.ConnectAsync();
        Assert.False(model.ShowDiagnostics);
        var view = new KvmWorkspaceView { DataContext = model };
        var window = new Window { Width = 800, Height = 600, Content = view };
        window.Show();
        try
        {
            Dispatcher.UIThread.RunJobs();
            var viewport = view.FindControl<Border>("Viewport")!;
            var center = viewport.TranslatePoint(new Point(viewport.Bounds.Width / 2, viewport.Bounds.Height / 2), window)!.Value;
            session.FailInput = true;
            window.MouseDown(center, MouseButton.Left);
            await WaitFor(() => model.ShowDiagnostics);
            Assert.True(model.ShowDiagnostics);
            Assert.False(model.IsConnected);
            Assert.True(model.CanConnect);
            session.FailDispose = true;
            await model.DisconnectAsync();
            Assert.Contains("fixture cleanup", model.Status);
            Assert.True(model.ShowDiagnostics);
            session.FailInput = session.FailDispose = false;
            await model.ConnectAsync();
            Assert.False(model.ShowDiagnostics);
            Assert.True(model.IsConnected);
            await model.DisconnectAsync();
            Assert.True(model.ShowDiagnostics);
        }
        finally { window.Close(); }
    });

    [Fact]
    public Task SlowPasteValidatesBeforeSendingAndCancelsBetweenCharacters() => Run(async () =>
    {
        var session = new RecordingConsole();
        await using var owner = new ConsoleSessionOwner(() => Task.FromResult<IKvmSession>(session));
        await using var model = new KvmWorkspaceViewModel(new ServerRecord(), () => Task.FromResult<StoredCredential?>(new("fixture", "fixture")), owner);
        await model.ConnectAsync();
        await model.PasteAsync("abc中文");
        Assert.Empty(session.Keys);
        Assert.NotEmpty(model.PasteNotice);
        model.PasteInterval = 10;
        await model.PasteAsync("A!\r\n\t ");
        Assert.Equal(new uint[] { 65, 33, 0xff0d, 0xff09, 32 }, session.Keys.Where(k => k.Down == 1).Select(k => k.Key));
        Assert.Equal(session.Keys.Count / 2, session.Keys.Count(k => k.Down == 0));
        session.Keys.Clear();
        model.PasteInterval = 1000;
        var paste = model.PasteAsync("abc");
        Assert.True(model.IsPasting);
        await WaitFor(() => session.Keys.Count >= 2);
        Assert.Equal(new[] { (1, (uint)'a'), (0, (uint)'a') }, session.Keys);
        model.CancelPaste();
        await paste;
        Assert.False(model.IsPasting);
        Assert.Equal(2, session.Keys.Count);
        session.Keys.Clear();
        paste = model.PasteAsync("abc");
        await model.DisconnectAsync();
        await paste;
        Assert.Equal(2, session.Keys.Count);
    });

    private static async Task WaitFor(Func<bool> condition)
    {
        for (var i = 0; i < 200 && !condition(); i++)
        {
            Dispatcher.UIThread.RunJobs();
            await Task.Delay(10);
        }
        Assert.True(condition());
    }

    private static async Task Run(Func<Task> test)
    {
        using var session = HeadlessUnitTestSession.StartNew(typeof(KvmTestApp));
        await session.Dispatch(async () => { await test(); return true; }, CancellationToken.None);
    }

    private sealed class RecordingConsole : IKvmSession
    {
        public event Action<KvmFrame>? FrameReceived { add { } remove { } }
        public event Action<string>? Failed { add { } remove { } }
        public event Action? Closed { add { } remove { } }
        public KvmFrame LatestFrame => Frame(255, 0, 0);
        public bool IsConnected => true;
        public List<(int Down, uint Key)> Keys { get; } = new();
        public List<(byte Buttons, ushort X, ushort Y)> Pointers { get; } = new();
        public bool FailInput, FailDispose;
        public Task SendKeyAsync(int down, uint keysym) { Keys.Add((down, keysym)); return InputResult(); }
        public Task SendPointerAsync(byte buttons, ushort x, ushort y) { Pointers.Add((buttons, x, y)); return InputResult(); }
        private Task InputResult() => FailInput ? Task.FromException(new System.Net.WebSockets.WebSocketException("fixture aborted socket")) : Task.CompletedTask;
        public ValueTask DisposeAsync() => FailDispose ? ValueTask.FromException(new IOException("fixture cleanup")) : ValueTask.CompletedTask;
        public static KvmFrame Frame(byte r, byte g, byte b) => new(4, 2, 16, "", Enumerable.Range(0, 8).SelectMany(_ => new byte[] { r, g, b, 255 }).ToArray());
    }
}
