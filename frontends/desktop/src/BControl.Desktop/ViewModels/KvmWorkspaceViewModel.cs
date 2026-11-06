using BControl.Core.Media;
using BControl.Core.Localization;
using BControl.Core.Kvm;
using BControl.Core.Native;
using BControl.Core.Redfish;
using BControl.Desktop.Services;

namespace BControl.Desktop.ViewModels;
public sealed class KvmWorkspaceViewModel : ViewModelBase, IAsyncDisposable
{
    private readonly Func<Task<StoredCredential?>> _getCredential;
    private IKvmSession? _session;
    private KvmInputStream? _input;
    private KvmVideoStream? _video;
    private Action<KvmFrame>? _frameHandler;
    private Action<string>? _failureHandler;
    private Action? _closedHandler;
    private bool _sharedConnection;
    private byte _pointerButtons;
    private ushort _pointerX, _pointerY;
    private readonly ConsoleSessionOwner? _owner;
    private bool _disposed;
    private bool _inputFailed;
    private bool _showDiagnostics;
    public bool ShowDiagnostics { get => _showDiagnostics; private set => SetProperty(ref _showDiagnostics, value); }
    private bool _busy;
    public bool IsBusy
    {
        get => _busy;
        private set
        {
            if (SetProperty(ref _busy, value))
                RaiseChanged(nameof(CanConnect));
        }
    }

    public Func<Task<MediaWorkspaceViewModel?>>? OpenMedia { get; set; }
    private MediaWorkspaceViewModel? _media;
    public MediaWorkspaceViewModel? Media { get => _media; set => SetProperty(ref _media, value); }
    private bool _showMedia;
    public bool ShowMedia { get => _showMedia; set => SetProperty(ref _showMedia, value); }
    public ServerControlViewModel CreatePowerControl() => new(Record, _getCredential);

    public bool CanConnect => !IsBusy && !IsConnected && !_disposed;
    public Func<Task<bool>>? RecoverAuthentication { get; set; }
    public ServerRecord Record { get; }

    private string _url;
    public string Url { get => _url; set => SetProperty(ref _url, value); }

    private string _status = Loc.T("kvm.notConnected");
    public string Status { get => _status; set => SetProperty(ref _status, value); }

    private KvmFrame? _frame;
    public KvmFrame? Frame { get => _frame; set => SetProperty(ref _frame, value); }
    public bool IsConnected => !_inputFailed && _session?.IsConnected == true;

    public KvmWorkspaceViewModel(ServerRecord record, Func<Task<StoredCredential?>> getCredential, ConsoleSessionOwner? owner = null)
    {
        Record = record;
        _owner = owner;
        _getCredential = getCredential;
        _url = "";
    }

    public sealed record HttpChoice(ConsoleHttpConnection Connection, string Title);
    public IReadOnlyList<HttpChoice> HttpChoices { get; } = [
        new(ConsoleHttpConnection.Html5, Loc.T("kvm.http.html5")),
        new(ConsoleHttpConnection.Legacy, Loc.T("kvm.http.legacy")),
        new(ConsoleHttpConnection.Redfish, "Redfish")];
    private bool _needsHttpChoice;
    public bool NeedsHttpChoice { get => _needsHttpChoice; private set => SetProperty(ref _needsHttpChoice, value); }
    private IReadOnlyList<ConsoleProtocolChoice> _protocolChoices = [];
    public IReadOnlyList<ConsoleProtocolChoice> ProtocolChoices {
        get => _protocolChoices;
        private set { SetProperty(ref _protocolChoices, value); RaiseChanged(nameof(NeedsProtocolChoice)); }
    }
    public bool NeedsProtocolChoice => ProtocolChoices.Count != 0;
    public HttpChoice? SelectedHttpChoice { get; set; }
    public ConsoleProtocolChoice? SelectedProtocolChoice { get; set; }
    public async Task ApplyConnectionChoiceAsync()
    {
        if (NeedsHttpChoice) {
            if (SelectedHttpChoice == null) return;
            Record.ConsoleHttpConnection = SelectedHttpChoice.Connection;
            Record.ConsoleProtocol = null;
        } else if (NeedsProtocolChoice) {
            if (SelectedProtocolChoice == null) return;
            Record.ConsoleProtocol = SelectedProtocolChoice;
        } else return;
        NeedsHttpChoice = false; ProtocolChoices = [];
        await ConnectAsync();
    }
    private CancellationTokenSource? _connecting;
    public void CancelConnection() => _connecting?.Cancel();

    private CancellationTokenSource? _paste;
    private int _pasteInterval = 50;
    public int PasteInterval { get => _pasteInterval; set => SetProperty(ref _pasteInterval, Math.Clamp(value, 10, 1000)); }
    public bool IsPasting => _paste != null;
    private string _pasteNotice = "";
    public string PasteNotice { get => _pasteNotice; private set => SetProperty(ref _pasteNotice, value); }
    public void CancelPaste() => _paste?.Cancel();

    public async Task PasteAsync(string text)
    {
        if (!IsConnected || IsPasting)
            return;
        var keys = BControl.Core.Input.KvmPaste.Plan(text);
        if (keys == null)
        {
            PasteNotice = Loc.T("kvm.pasteUnsupported");
            return;
        }
        if (keys.Length == 0)
        {
            PasteNotice = Loc.T("sol.clipboardEmpty");
            return;
        }
        using var cancellation = new CancellationTokenSource();
        _paste = cancellation;
        RaiseChanged(nameof(IsPasting));
        var session = _session;
        var interval = PasteInterval;
        try
        {
            // Release local modifiers before typing clipboard characters.
            foreach (var held in _heldKeys.ToArray())
                await SendKeyAsync(0, held);
            for (var i = 0; i < keys.Length; i++)
            {
                cancellation.Token.ThrowIfCancellationRequested();
                if (!ReferenceEquals(session, _session) || !IsConnected)
                    throw new OperationCanceledException();
                await SendChordAsync([keys[i]]);
                if (!IsConnected)
                    throw new OperationCanceledException();
                PasteNotice = Loc.F("kvm.pasteProgress", ("sent", (i + 1).ToString()), ("total", keys.Length.ToString()));
                if (i + 1 < keys.Length)
                    await Task.Delay(interval, cancellation.Token);
            }
            PasteNotice = "";
        }
        catch (OperationCanceledException) { PasteNotice = Loc.T("sol.pasteCancelled"); }
        finally
        {
            _paste = null;
            RaiseChanged(nameof(IsPasting));
        }
    }

    public async Task ConnectAsync()
    {
        if (!CanConnect)
            return;
        using var connecting = new CancellationTokenSource();
        _connecting = connecting;
        IsBusy = true;
        var retryAuthentication = false;
        try
        {
            await DisconnectAsync();
            ShowDiagnostics = false;
            NeedsHttpChoice = false; ProtocolChoices = [];
            _inputFailed = false;
            Status = Loc.T("kvm.connecting");
            if (!string.IsNullOrWhiteSpace(Url))
                _session = await KvmSession.ConnectAsync(Url.Trim(), Record.CaFile, null, null, Record.CertPolicy, Record.Timeout?.Milliseconds ?? 8000, connecting.Token, Record.MinimumTls, await Record.ResolveProxyAsync());
            else
            {
                var credential = await _getCredential();
                if (credential == null)
                {
                    ReportFailure(Loc.T("error.credentialsUnavailable"));
                    return;
                }

                _session = _owner != null ? await _owner.AcquireAsync(connecting.Token) : await ConsoleConnectionFactory.ConnectAsync(Record, credential, connecting.Token);
                _sharedConnection = _owner != null;
            }

            if (_disposed || connecting.IsCancellationRequested)
            {
                await DisconnectAsync();
                return;
            }

            var current = _session;
            _inputFailed = false;
            _input = new KvmInputStream(current);
            var video = new KvmVideoStream(async frame => await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
            {
                if (ReferenceEquals(_session, current))
                {
                    Frame = frame;
                    if (current.IsConnected && !_inputFailed)
                    {
                        ShowDiagnostics = false;
                        Status = Loc.T("kvm.connected");
                        RaiseChanged(nameof(IsConnected));
                        RaiseChanged(nameof(CanConnect));
                    }
                }
            }));
            _video = video;
            _frameHandler = video.Publish;
            _session.FrameReceived += _frameHandler;
            _failureHandler = reason => Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                if (ReferenceEquals(_session, current))
                    ReportFailure(reason);
            });
            _closedHandler = () => Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                if (!ReferenceEquals(_session, current))
                    return;
                if (!ShowDiagnostics)
                    Status = Loc.T("kvm.disconnected");
                CancelPaste();
                ShowDiagnostics = true;
                RaiseChanged(nameof(IsConnected));
                RaiseChanged(nameof(CanConnect));
            });
            _session.Failed += _failureHandler;
            _session.Closed += _closedHandler;
            Frame = _session.LatestFrame;
            Status = Loc.T("kvm.connected");
            RaiseChanged(nameof(IsConnected));
        }
        catch (OperationCanceledException) when (connecting.IsCancellationRequested) {
            await DisconnectAsync();
            Status = Loc.T("kvm.disconnected");
        }
        catch (Exception ex)
        {
            await DisconnectAsync();
            ReportFailure(ex.Message);
            NeedsHttpChoice = ex is ConsoleHttpSelectionRequiredException;
            ProtocolChoices = ConsoleService.Choices(ex);
            retryAuthentication = ex is ConsoleFailureException { IsCredentialFailure: true };
        }
        finally
        {
            _connecting = null;
            IsBusy = false;
            RaiseChanged(nameof(IsConnected));
            RaiseChanged(nameof(CanConnect));
        }

        if (retryAuthentication && !_disposed && RecoverAuthentication != null && await RecoverAuthentication())
            await ConnectAsync();
    }

    /// <summary>焦点丢失时调用：释放所有按下的键与鼠标键。</summary>
    public async Task ReleaseAllAsync(IReadOnlyList<uint> pressedKeysyms, byte lastButtons, ushort lastX, ushort lastY)
    {
        if (_session == null)
            return;
        foreach (var keysym in pressedKeysyms)
            await SendKeyAsync(0, keysym);
        if (lastButtons != 0)
            await SendPointerAsync(0, lastX, lastY);
    }

    private readonly HashSet<uint> _heldKeys = new();
    private readonly SemaphoreSlim _chord = new(1);
    public async Task SendChordAsync(uint[] keysyms)
    {
        var keys = BControl.Core.Input.RemoteKeys.Order(keysyms);
        if (keys == null || !IsConnected)
            return;
        await _chord.WaitAsync();
        try
        {
            var added = keys.Where(key => !_heldKeys.Contains(key)).ToArray();
            if (added.Length > 0) await SendInputAsync(new KvmInputEvent.Chord(added));
        }
        finally
        {
            _chord.Release();
        }
    }

    public Task SendKeyAsync(int down, uint keysym)
    {
        if (down != 0)
            _heldKeys.Add(keysym);
        else
            _heldKeys.Remove(keysym);
        return SendInputAsync(new KvmInputEvent.Key(down, keysym));
    }

    public Task SendPointerAsync(byte buttons, ushort x, ushort y)
    {
        _pointerButtons = buttons;
        _pointerX = x;
        _pointerY = y;
        return SendInputAsync(new KvmInputEvent.Pointer(buttons, x, y));
    }

    public Task SendScrollAsync(byte buttons, ushort x, ushort y, sbyte wheel)
    {
        if (_session?.SupportsScroll != true || wheel == 0) return Task.CompletedTask;
        return SendInputAsync(new KvmInputEvent.Scroll(buttons, x, y, wheel));
    }

    private void ReportFailure(string reason)
    {
        CancelPaste();
        _inputFailed = true;
        ShowDiagnostics = true;
        Status = Loc.F("kvm.connectionFailed", ("reason", reason));
        RaiseChanged(nameof(IsConnected));
        RaiseChanged(nameof(CanConnect));
    }

    private async Task SendInputAsync(KvmInputEvent input)
    {
        var session = _session;
        var stream = _input;
        if (session == null || stream == null || !IsConnected)
            return;
        try
        {
            await stream.SendAsync(input);
        }
        catch (Exception ex)
        {
            if (ReferenceEquals(_session, session))
                ReportFailure(ex.Message);
        }
    }

    public async Task DisconnectAsync()
    {
        CancelPaste();
        await _chord.WaitAsync();
        try
        {
            var session = _session;
            var input = _input;
            var video = _video;
            _session = null; _input = null; _video = null;
            if (session != null && _frameHandler != null) session.FrameReceived -= _frameHandler;
            if (session != null && _failureHandler != null) session.Failed -= _failureHandler;
            if (session != null && _closedHandler != null) session.Closed -= _closedHandler;
            _frameHandler = null; _failureHandler = null; _closedHandler = null;
            if (session == null)
                return;
            string? error = null;
            try
            {
                if (session.IsConnected && input != null)
                {
                    foreach (var key in _heldKeys.ToArray())
                        await input.SendAsync(new KvmInputEvent.Key(0, key));
                    if (_pointerButtons != 0)
                        await input.SendAsync(new KvmInputEvent.Pointer(0, _pointerX, _pointerY));
                }
            }
            catch (Exception ex) { error = ex.Message; }
            try
            {
                if (input != null) await input.DisposeAsync();
                if (video != null) await video.DisposeAsync();
            }
            catch (Exception ex) { error = ex.Message; }
            try
            {
                if (_sharedConnection && _owner != null)
                    await _owner.ReleaseAsync();
                else
                    await session.DisposeAsync();
            }
            catch (Exception ex) { error = ex.Message; }
            finally
            {
                _heldKeys.Clear();
                _pointerButtons = 0;
                _sharedConnection = false;
                Frame = null;
                ShowDiagnostics = true;
                if (error != null)
                    ReportFailure(error);
                else
                    Status = Loc.T("kvm.disconnected");
                RaiseChanged(nameof(IsConnected));
                RaiseChanged(nameof(CanConnect));
            }
        }
        finally
        {
            _chord.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        _disposed = true;
        CancelConnection();
        await DisconnectAsync();
    }
}
