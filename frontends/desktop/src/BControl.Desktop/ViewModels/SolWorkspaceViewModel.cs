using System.Text;
using BControl.Core.Localization;
using BControl.Core.Ipmi;
using BControl.Core.Native;
using BControl.Desktop.Services;
using Porta.Pty;

namespace BControl.Desktop.ViewModels;
/// <summary>把 SOL 字节流桥接为 IPtyConnection；不启动任何本地进程。</summary>
public sealed class SolPtyConnection : IPtyConnection
{
    private readonly ISerialSession _session;
    private readonly SolStream _reader;
    private readonly SolWriteStream _writer;
    private int _disposed;
    public SolPtyConnection(ISerialSession session)
    {
        _session = session;
        _reader = new SolStream(session);
        _writer = new SolWriteStream(session);
        session.Received += OnReceived;
    }

    private void OnReceived(byte[] data) => _reader.Feed(data);
    public event EventHandler<PtyExitedEventArgs>? ProcessExited;
    public Stream ReaderStream => _reader;
    public Stream WriterStream => _writer;
    public bool SupportsCancellableRead => true;
    public int Pid => 0;
    public int ExitCode => 0;

    public bool WaitForExit(int milliseconds)
    {
        // 会话生命周期由显式断开驱动；未断开时等待超时后返回 false。
        if (_disposed != 0)
            return true;
        var deadline = Environment.TickCount64 + milliseconds;
        while (Environment.TickCount64 < deadline && _disposed == 0)
            Thread.Sleep(Math.Min(50, (int)(deadline - Environment.TickCount64)));
        return _disposed != 0;
    }

    public void Kill() => _ = _session.DisposeAsync();
    public void Resize(int cols, int rows)
    {
    // SOL 无标准窗口协商；终端尺寸保持本地显示状态。
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        _session.Received -= OnReceived;
        _reader.Complete();
    // 不伪造进程退出事件：会话生命周期由显式断开驱动。
    }

    private sealed class SolStream : Stream
    {
        private readonly ISerialSession _session;
        private readonly Queue<byte> _buffer = new();
        private readonly SemaphoreSlim _dataAvailable = new(0);
        private bool _completed;
        public SolStream(ISerialSession session) => _session = session;
        public void Feed(byte[] data)
        {
            lock (_buffer)
                foreach (var b in data)
                    _buffer.Enqueue(b);
            _dataAvailable.Release();
        }

        public void Complete()
        {
            _completed = true;
            _dataAvailable.Release();
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer, offset, count).GetAwaiter().GetResult();
        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (count == 0)
                return 0;
            while (true)
            {
                lock (_buffer)
                {
                    if (_buffer.Count > 0)
                    {
                        var read = Math.Min(count, _buffer.Count);
                        for (var i = 0; i < read; i++)
                            buffer[offset + i] = _buffer.Dequeue();
                        return read;
                    }
                }

                if (_completed)
                    return 0;
                await _dataAvailable.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class SolWriteStream : Stream
    {
        private readonly ISerialSession _session;
        public SolWriteStream(ISerialSession session) => _session = session;
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (!_session.CanWrite) return;
            var copy = new byte[count];
            Array.Copy(buffer, offset, copy, 0, count);
            _session.WriteAsync(copy).GetAwaiter().GetResult();
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (!_session.CanWrite) return;
            var copy = new byte[count];
            Array.Copy(buffer, offset, copy, 0, count);
            await _session.WriteAsync(copy, cancellationToken).ConfigureAwait(false);
        }
    }
}

public sealed class SolWorkspaceViewModel : ViewModelBase, IAsyncDisposable
{
    private readonly ServerRecord _record;
    private readonly Func<Task<StoredCredential?>> _getCredential;
    private IpmiConnection? _connection;
    private ISerialSession? _sol;
    private SolPtyConnection? _pty;
    private bool _disposed;
    private bool _isBusy;
    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetProperty(ref _isBusy, value))
                RaiseChanged(nameof(CanConnect));
        }
    }

    public bool CanWrite => _sol?.CanWrite == true;
    public bool IsConnected => _sol?.PumpActive == true;
    public bool CanConnect => !IsBusy && !IsConnected && !_disposed;
    public Func<Task<bool>>? RecoverAuthentication { get; set; }

    private CancellationTokenSource? _paste;
    public ServerRecord Record => _record;

    private string _host;
    public string Host { get => _host; set => SetProperty(ref _host, value); }

    private ushort _port = 623;
    public ushort Port { get => _port; set => SetProperty(ref _port, value); }

    private bool _suite3Confirmed;
    public bool Suite3Confirmed { get => _suite3Confirmed; set => SetProperty(ref _suite3Confirmed, value); }

    private string _status = Loc.T("kvm.notConnected");
    public string Status { get => _status; set => SetProperty(ref _status, value); }
    public SolPtyConnection? Connection => _pty;

    public SolWorkspaceViewModel(ServerRecord record, Func<Task<StoredCredential?>> getCredential)
    {
        _record = record;
        _getCredential = getCredential;
        (_host, _port) = ParseAddress(record.Address, record.Protocol);
        _suite3Confirmed = record.Suite3Confirmed;
    }

    public static (string Host, ushort Port) ParseAddress(string address, uint protocol)
    {
        var text = address.Trim();
        if (text.Contains("://", StringComparison.Ordinal))
        {
            if (Uri.TryCreate(text, UriKind.Absolute, out var uri))
                return (uri.Host, !uri.IsDefaultPort && uri.Port > 0 ? (ushort)uri.Port : (ushort)623);
        }

        if (text.StartsWith('['))
        {
            var closing = text.IndexOf(']');
            if (closing > 1)
            {
                var host = text[1..closing];
                if (closing + 2 < text.Length && text[closing + 1] == ':' && ushort.TryParse(text[(closing + 2)..], out var port))
                    return (host, port);
                return (host, 623);
            }
        }

        var firstColon = text.IndexOf(':');
        var lastColon = text.LastIndexOf(':');
        if (firstColon > 0 && firstColon == lastColon && ushort.TryParse(text[(lastColon + 1)..], out var parsedPort))
            return (text[..lastColon], parsedPort);
        return (text, 623);
    }

    public async Task ConnectAsync()
    {
        if (!CanConnect)
            return;
        IsBusy = true;
        bool retryAuthentication = false;
        try
        {
            var credential = await _getCredential();
            if (credential == null)
            {
                Status = Loc.T("error.credentialsUnavailable");
                return;
            }

            await DisconnectAsync();
            if (_disposed)
                return;
            Status = Loc.T("sol.preparing");
            var proxy = await _record.ResolveProxyAsync();
            _connection = await IpmiConnection.OpenAsync(Host, Port, credential.Username, credential.Password, _suite3Confirmed, CancellationToken.None, proxy, _record.Timeout);
            try
            {
                var config = await _connection.GetSolConfigAsync();
                if (config == null) throw new SolUnavailableException(false);
                if (config.ConfigurationKnown && !config.Enabled) throw new SolUnavailableException(true);
                _sol = await _connection.OpenSolAsync();
            }
            catch (SolUnavailableException)
            {
                var capabilities = await _connection.ProbeAsync();
                if (!capabilities.AlternateSerialCandidate) throw;
                await _connection.DisposeAsync(); _connection = null;
                if (_disposed) return;
                _sol = await BControl.Core.Transport.NativeSerialSession.OpenAsync(Host, credential.Username,
                    credential.Password, _record.CaFile, _record.CertPolicy, _record.MinimumTls, proxy, _record.Timeout);
            }
            if (_disposed)
            {
                await DisconnectAsync();
                return;
            }

            _pty = new SolPtyConnection(_sol);
            var activeSol = _sol;
            _sol.Ended += state => Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                if (_disposed || !ReferenceEquals(_sol, activeSol))
                    return;
                _pty?.Dispose();
                _pty = null;
                RaiseChanged(nameof(Connection));
                Status = state.Status == 0 ? Loc.T("sol.disconnected") : Loc.F("kvm.connectionFailed", ("reason", Bc.StatusText(state.Status)));
                RaiseChanged(nameof(IsConnected));
                RaiseChanged(nameof(CanWrite));
                RaiseChanged(nameof(CanConnect));
            });
            _sol.WriteAccessChanged += () => Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                if (_disposed || !ReferenceEquals(_sol, activeSol)) return;
                RaiseChanged(nameof(CanWrite));
                Status = Loc.T(CanWrite ? "kvm.connected" : "sol.readOnly");
            });
            Status = Loc.T(CanWrite ? "kvm.connected" : "sol.readOnly");
            RaiseChanged(nameof(CanWrite));
            RaiseChanged(nameof(Connection));
        }
        catch (Suite3ConfirmationRequiredException)
        {
            Status = Loc.T("sol.suite3Required");
            await DisconnectAsync();
            Status = Loc.T("sol.suite3Required");
        }
        catch (Exception ex)
        {
            await DisconnectAsync();
            Status = Loc.F("kvm.connectionFailed", ("reason", ex.Message));
            retryAuthentication = ex is BcException { Status: Bc.AuthenticationFailed };
        }
        finally
        {
            IsBusy = false;
            RaiseChanged(nameof(IsConnected));
            RaiseChanged(nameof(CanWrite));
            RaiseChanged(nameof(CanConnect));
        }

        if (retryAuthentication && !_disposed && RecoverAuthentication != null && await RecoverAuthentication())
            await ConnectAsync();
    }

    public Func<bool>? ApplicationCursor { get; set; }
    public Func<bool>? BracketedPaste { get; set; }

    public void CancelPaste() => _paste?.Cancel();
    public async Task SendKeysAsync(uint[] keys)
    {
        var bytes = BControl.Core.Input.RemoteKeys.TerminalBytes(keys, ApplicationCursor?.Invoke() == true);
        if (bytes == null || !CanWrite || _sol == null)
            return;
        try
        {
            await _sol.WriteAsync(bytes);
        }
        catch (Exception ex)
        {
            Status = ex.Message;
        }
    }

    public async Task PasteAsync(string text, bool slow)
    {
        var sol = _sol;
        if (!CanWrite || sol == null || _paste != null)
            return;
        using var cancellation = new CancellationTokenSource();
        _paste = cancellation;
        try
        {
            var data = Encoding.UTF8.GetBytes(text.Replace("\r\n", "\r").Replace("\n", "\r"));
            if (data.Length > 1024 * 1024)
            {
                Status = Loc.T("sol.pasteTruncated");
                return;
            }

            var bracketed = BracketedPaste?.Invoke() == true;
            if (bracketed)
                await sol.WriteAsync("\u001b[200~"u8.ToArray(), cancellation.Token);
            try
            {
                for (var offset = 0; offset < data.Length; offset += slow ? 64 : 4096)
                {
                    cancellation.Token.ThrowIfCancellationRequested();
                    var chunk = data.AsSpan(offset, Math.Min(slow ? 64 : 4096, data.Length - offset)).ToArray();
                    await sol.WriteAsync(chunk, cancellation.Token);
                    if (slow)
                        await Task.Delay(25, cancellation.Token);
                }
            }
            finally
            {
                if (bracketed && sol.PumpActive == true)
                    await sol.WriteAsync("\u001b[201~"u8.ToArray());
            }
        }
        catch (OperationCanceledException)
        {
            Status = Loc.T("sol.pasteCancelled");
        }
        catch (Exception ex)
        {
            Status = Loc.F("kvm.connectionFailed", ("reason", ex.Message));
        }
        finally
        {
            _paste = null;
        }
    }

    public async Task DisconnectAsync()
    {
        _paste?.Cancel();
        var sol = _sol;
        var connection = _connection;
        _sol = null;
        _connection = null;
        Status = Loc.T("sol.disconnected");
        RaiseChanged(nameof(IsConnected));
        RaiseChanged(nameof(CanWrite));
        RaiseChanged(nameof(CanConnect));
        var pty = _pty;
        _pty = null;
        RaiseChanged(nameof(Connection));
        string? error = null;
        try
        {
            if (sol != null)
                await sol.DisposeAsync();
        }
        catch (Exception ex) { error = ex.Message; }
        finally
        {
            pty?.Dispose();
        }
        try
        {
            if (connection != null)
                await connection.DisposeAsync();
        }
        catch (Exception ex) { error = ex.Message; }
        Status = error ?? Loc.T("kvm.disconnected");
        RaiseChanged(nameof(Connection));
        RaiseChanged(nameof(IsConnected));
        RaiseChanged(nameof(CanWrite));
        RaiseChanged(nameof(CanConnect));
    }

    public async ValueTask DisposeAsync()
    {
        _disposed = true;
        await DisconnectAsync();
    }
}
