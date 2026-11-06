using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Input;
using Avalonia.Input.Raw;
using Avalonia.Threading;
using BControl.Desktop.Views;
using Porta.Pty;

namespace BControl.Desktop.Tests;

[Collection("Avalonia UI")]
public sealed class SolTerminalTests
{
    [Fact]
    public async Task RemoteTerminalRoutesInputAcrossReloadWithoutLocalShell()
    {
        using var session = HeadlessUnitTestSession.StartNew(typeof(KvmTestApp));
        await session.Dispatch(async () =>
        {
            var view = new SolWorkspaceView();
            var terminal = view.FindControl<SolTerminalControl>("Terminal")!;
            Assert.Equal(string.Empty, terminal.Process);
            using var connection = new RecordingConnection();
            var window = new Window { Width = 800, Height = 600, Content = view };
            window.Show();
            try
            {
                Dispatcher.UIThread.RunJobs();
                terminal.Connection = connection;
                Dispatcher.UIThread.RunJobs();
                terminal.Terminal!.Write("\u001b[?9001h");
                Assert.True(terminal.Terminal.Win32InputMode);
                window.KeyPress(Key.H, RawInputModifiers.None, PhysicalKey.None, "h");
                window.KeyTextInput("h");
                window.KeyRelease(Key.H, RawInputModifiers.None, PhysicalKey.None, "h");
                window.KeyPress(Key.E, RawInputModifiers.None, PhysicalKey.None, "e");
                window.KeyRelease(Key.E, RawInputModifiers.None, PhysicalKey.None, "e");
                window.KeyPress(Key.L, RawInputModifiers.None, PhysicalKey.None, "l");
                window.KeyRelease(Key.L, RawInputModifiers.None, PhysicalKey.None, "l");
                window.KeyTextInput("lo");
                window.KeyPress(Key.Enter, RawInputModifiers.None, PhysicalKey.None, null);
                window.KeyPress(Key.Up, RawInputModifiers.None, PhysicalKey.None, null);
                window.KeyPress(Key.Escape, RawInputModifiers.None, PhysicalKey.None, null);
                window.KeyRelease(Key.Escape, RawInputModifiers.None, PhysicalKey.None, null);
                window.KeyPress(Key.Back, RawInputModifiers.None, PhysicalKey.None, null);
                window.KeyPress(Key.C, RawInputModifiers.Control, PhysicalKey.None, "c");
                window.KeyTextInput("c");
                window.KeyRelease(Key.C, RawInputModifiers.None, PhysicalKey.None, null);
                await WaitFor(() => connection.Text == "hello\r\u001b[A\u001b\u007f\u0003");
                window.Content = null;
                Dispatcher.UIThread.RunJobs();
                window.Content = view;
                Dispatcher.UIThread.RunJobs();
                terminal.Connection = connection;
                terminal.Focus();
                Dispatcher.UIThread.RunJobs();
                window.KeyTextInput("again");
                await WaitFor(() => connection.Text.EndsWith("again"));
                Assert.False(connection.Disposed);
                Assert.Equal(string.Empty, terminal.Process);
                terminal.Connection = null;
                window.KeyTextInput("ignored");
                Assert.DoesNotContain("ignored", connection.Text);
            }
            finally { window.Close(); }
            return true;
        }, CancellationToken.None);
    }

    [Fact]
    public async Task ConnectionAssignedBeforeLoadSurvivesReparenting()
    {
        using var session = HeadlessUnitTestSession.StartNew(typeof(KvmTestApp));
        await session.Dispatch(async () =>
        {
            using var connection = new RecordingConnection();
            var terminal = new SolTerminalControl { Connection = connection };
            var window = new Window { Width = 800, Height = 600, Content = terminal };
            window.Show();
            try
            {
                Dispatcher.UIThread.RunJobs();
                window.KeyTextInput("first");
                await WaitFor(() => connection.Text == "first");
                window.Content = null;
                Dispatcher.UIThread.RunJobs();
                window.Content = terminal;
                Dispatcher.UIThread.RunJobs();
                window.KeyPress(Key.Tab, RawInputModifiers.None, PhysicalKey.None, null);
                window.KeyTextInput("second");
                await WaitFor(() => connection.Text == "first\tsecond");
                Assert.False(connection.Disposed);
            }
            finally { window.Close(); }
            return true;
        }, CancellationToken.None);
    }

    [Fact]
    public async Task RemoteEofSuppressesLocalProcessExitMessage()
    {
        using var session = HeadlessUnitTestSession.StartNew(typeof(KvmTestApp));
        await session.Dispatch(async () =>
        {
            using var connection = new RecordingConnection();
            var terminal = new SolTerminalControl { Connection = connection };
            bool? suppressed = null;
            terminal.WritingMessage += (_, message) => suppressed = message.Handled;
            var window = new Window { Width = 800, Height = 600, Content = terminal };
            window.Show();
            try
            {
                Dispatcher.UIThread.RunJobs();
                connection.CompleteReader();
                await WaitFor(() => suppressed.HasValue);
                Assert.True(suppressed);
            }
            finally { window.Close(); }
            return true;
        }, CancellationToken.None);
    }

    private static async Task WaitFor(Func<bool> condition)
    {
        for (var i = 0; i < 100 && !condition(); i++)
        {
            Dispatcher.UIThread.RunJobs();
            await Task.Delay(10);
        }
        Assert.True(condition());
    }

    private sealed class RecordingConnection : IPtyConnection
    {
        private readonly MemoryStream _writer = new();
        public string Text => System.Text.Encoding.UTF8.GetString(_writer.ToArray());
        public bool Disposed;
        public Stream ReaderStream { get; } = new WaitingStream();
        private bool _ended;
        public void CompleteReader() { _ended = true; ((WaitingStream)ReaderStream).Complete(); }
        public Stream WriterStream => _writer;
        public bool SupportsCancellableRead => true;
        public int Pid => 0;
        public int ExitCode => 0;
        public event EventHandler<PtyExitedEventArgs>? ProcessExited { add { } remove { } }
        public bool WaitForExit(int milliseconds) => _ended || Disposed;
        public void Resize(int cols, int rows) { }
        public void Kill() => throw new InvalidOperationException("Remote connection must not be killed by the view");
        public void Dispose() { Disposed = true; _writer.Dispose(); }
    }

    private sealed class WaitingStream : MemoryStream
    {
        private readonly TaskCompletionSource _completed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void Complete() => _completed.TrySetResult();
        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            await _completed.Task.WaitAsync(cancellationToken);
            return 0;
        }
    }
}
