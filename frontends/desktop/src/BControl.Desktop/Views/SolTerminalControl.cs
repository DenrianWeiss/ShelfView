using Avalonia.Input;
using Avalonia.Interactivity;
using BControl.Core.Input;
using System.Text;
using Iciclecreek.Terminal;
using Porta.Pty;

namespace BControl.Desktop.Views;

public sealed class SolTerminalControl : TerminalControl
{
    protected override Type StyleKeyOverride => typeof(TerminalControl);

    private readonly SemaphoreSlim _inputGate = new(1);
    public event Action<Exception>? InputFailed;
    private IPtyConnection? _connection;
    private IPtyConnection? _attached;
    private bool _keySentText;

    public SolTerminalControl()
    {
        Process = string.Empty;
        WritingMessage += (_, e) => e.Handled = true;
        AddHandler(KeyDownEvent, OnRemoteKeyDown, RoutingStrategies.Tunnel);
        AddHandler(KeyUpEvent, (_, e) => { _keySentText = false; e.Handled = true; }, RoutingStrategies.Tunnel);
        AddHandler(TextInputEvent, OnRemoteTextInput, RoutingStrategies.Tunnel);
        Loaded += (_, _) => Attach();
        Unloaded += (_, _) =>
        {
            DetachConnection();
            _attached = null;
            _keySentText = false;
        };
    }

    public IPtyConnection? Connection
    {
        get => _connection;
        set
        {
            _connection = value;
            Attach();
        }
    }

    private async void OnRemoteKeyDown(object? sender, KeyEventArgs e)
    {
        // SOL carries VT bytes, never local ConPTY INPUT_RECORD sequences.
        e.Handled = true;
        _keySentText = false;
        var key = KeyMapping.ToKeysym(e);
        var control = e.KeyModifiers.HasFlag(KeyModifiers.Control);
        var alt = e.KeyModifiers.HasFlag(KeyModifiers.Alt);
        if (!control && !alt && !string.IsNullOrEmpty(e.KeySymbol)
            && e.KeySymbol.All(c => !char.IsControl(c)))
        {
            _keySentText = true;
            await SendAsync(Encoding.UTF8.GetBytes(e.KeySymbol));
            return;
        }
        if (key == 0)
            return; // IME composition is delivered through TextInput.
        var keys = new List<uint> { key };
        if (control) keys.Add(0xffe3);
        if (alt) keys.Add(0xffe9);
        if (e.KeyModifiers.HasFlag(KeyModifiers.Shift)) keys.Add(0xffe1);
        var bytes = RemoteKeys.TerminalBytes(keys, Terminal?.ApplicationCursorKeys == true);
        if (bytes != null)
        {
            _keySentText = key < 0xff00;
            await SendAsync(bytes);
        }
    }

    private async void OnRemoteTextInput(object? sender, TextInputEventArgs e)
    {
        e.Handled = true;
        if (!_keySentText && !string.IsNullOrEmpty(e.Text))
            await SendAsync(Encoding.UTF8.GetBytes(e.Text));
    }

    private async Task SendAsync(byte[] bytes)
    {
        var connection = _attached;
        if (connection == null)
            return;
        await _inputGate.WaitAsync();
        try
        {
            if (ReferenceEquals(connection, _attached))
            {
                await connection.WriterStream.WriteAsync(bytes);
                await connection.WriterStream.FlushAsync();
            }
        }
        catch (Exception ex) { InputFailed?.Invoke(ex); }
        finally { _inputGate.Release(); }
    }

    private void Attach()
    {
        if (!IsLoaded || ReferenceEquals(_attached, _connection))
            return;
        DetachConnection();
        _attached = null;
        if (_connection != null)
        {
            AttachConnection(_connection);
            _attached = _connection;
            Focus();
        }
    }
}
