using System.Collections.Generic;
using System.ComponentModel;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using BControl.Desktop.ViewModels;

namespace BControl.Desktop.Views;
public partial class KvmWorkspaceView : UserControl, Core.Kvm.IKvmDisplaySink
{
    private readonly Dictionary<Key, uint> _pressedKeysyms = new();
    private byte _buttons;
    private ushort _lastX, _lastY;
    private KvmWorkspaceViewModel? _viewModel;
    private WriteableBitmap? _bitmap;
    public KvmWorkspaceView()
    {
        InitializeComponent();
        Viewport.AddHandler(KeyDownEvent, OnKeyDown, RoutingStrategies.Tunnel);
        Viewport.AddHandler(KeyUpEvent, OnKeyUp, RoutingStrategies.Tunnel);
        DataContextChanged += (_, _) => BindViewModel();
        AttachedToVisualTree += (_, _) => BindViewModel();
        DetachedFromVisualTree += (_, _) =>
        {
            _viewModel?.CancelPaste();
            OnLostFocus(this, new RoutedEventArgs());
            if (_viewModel != null)
                _viewModel.PropertyChanged -= OnViewModelChanged;
            _viewModel = null;
            ClearBitmap();
        };
    }

    private async void OnToggleMedia(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is not { } model) return;
        if (model.ShowMedia) { model.ShowMedia = false; return; }
        if (model.OpenMedia == null) return;
        try
        {
            model.Media = await model.OpenMedia();
            model.ShowMedia = model.Media != null;
        }
        catch (Exception error) { model.Status = error.Message; }
    }

    private async void OnOpenPower(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is not { } model || TopLevel.GetTopLevel(this) is not Window owner)
            return;

        using var power = model.CreatePowerControl();
        await new KvmPowerWindow(power).ShowDialog(owner);
    }

    private async void OnSlowPaste(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is not { IsConnected: true, IsPasting: false } model || TopLevel.GetTopLevel(this)?.Clipboard is not { } clipboard)
            return;
        var text = await clipboard.TryGetTextAsync();
        if (ReferenceEquals(model, _viewModel))
            await model.PasteAsync(text ?? "");
    }

    private void OnCancelPaste(object? sender, RoutedEventArgs e) => _viewModel?.CancelPaste();

    private void BindViewModel()
    {
        if (_viewModel != null)
            _viewModel.PropertyChanged -= OnViewModelChanged;
        _viewModel = DataContext as KvmWorkspaceViewModel;
        if (_viewModel != null)
        {
            _viewModel.PropertyChanged += OnViewModelChanged;
            RenderFrame(_viewModel.Frame);
        }
        else
            ClearBitmap();
    }

    private void OnViewModelChanged(object? sender, PropertyChangedEventArgs args)
    {
        if (args.PropertyName == nameof(KvmWorkspaceViewModel.Frame))
            RenderFrame(_viewModel?.Frame);
    }

    private void ClearBitmap()
    {
        Screen.Source = null;
        _bitmap?.Dispose();
        _bitmap = null;
    }

    private void RenderFrame(Core.Kvm.KvmFrame? frame)
    {
        if (frame == null)
        {
            ClearBitmap();
            return;
        }

        DrawTile(Core.Kvm.KvmTile.FromFrame(frame));
    }

    public void DrawTile(Core.Kvm.KvmTile tile)
    {
        tile.Validate();
        if (_bitmap == null || _bitmap.PixelSize.Width != (int)tile.CanvasWidth || _bitmap.PixelSize.Height != (int)tile.CanvasHeight)
        {
            ClearBitmap();
            _bitmap = new WriteableBitmap(new PixelSize((int)tile.CanvasWidth, (int)tile.CanvasHeight), new Vector(96, 96), PixelFormat.Rgba8888, AlphaFormat.Opaque);
            using (var surface = _bitmap.Lock())
            {
                var blank = new byte[surface.RowBytes];
                for (var row = 0; row < surface.Size.Height; row++)
                    System.Runtime.InteropServices.Marshal.Copy(blank, 0, IntPtr.Add(surface.Address, row * surface.RowBytes), blank.Length);
            }
            Screen.Source = _bitmap;
        }

        using (var framebuffer = _bitmap.Lock())
        {
            var pixels = framebuffer.Address;
            var frameBytes = tile.PixelsRgba;
            var stride = framebuffer.RowBytes;
            var widthBytes = (int)tile.Width * 4;
            for (var row = 0; row < (int)tile.Height; row++)
            {
                var source = row * (int)tile.Stride;
                var target = (row + (int)tile.Y) * stride + (int)tile.X * 4;
                if (source + widthBytes <= frameBytes.Length && target + widthBytes <= framebuffer.Size.Height * stride)
                    System.Runtime.InteropServices.Marshal.Copy(frameBytes, source, IntPtr.Add(pixels, target), widthBytes);
            }
        }
        Screen.InvalidateVisual();
    }

    private async void OnExport(object? sender, RoutedEventArgs e)
    {
        if (_viewModel == null || TopLevel.GetTopLevel(this)is not Window owner)
            return;
        try
        {
            await StartupExport.ShowAsync(owner, Services.ConsoleConnectionFactory.Address(_viewModel.Record));
        }
        catch (Exception ex)
        {
            _viewModel.Status = ex.Message;
        }
    }

    private void OnCancelConnect(object? sender, RoutedEventArgs e) => _viewModel?.CancelConnection();
    private async void OnApplyConnectionChoice(object? sender, RoutedEventArgs e)
    {
        if (_viewModel != null) await _viewModel.ApplyConnectionChoiceAsync();
    }
    private async void OnConnect(object? sender, RoutedEventArgs e)
    {
        if (_viewModel != null)
            await _viewModel.ConnectAsync();
    }

    private async void OnDisconnect(object? sender, RoutedEventArgs e)
    {
        if (_viewModel != null)
            await _viewModel.DisconnectAsync();
    }

    private async void OnKeyDown(object? sender, KeyEventArgs e)
    {
        _viewModel?.CancelPaste();
        if (_viewModel == null || _viewModel.Frame == null)
            return;
        var keysym = KeyMapping.ToKeysym(e);
        if (keysym == 0)
            return;
        if (_pressedKeysyms.TryGetValue(e.Key, out var held))
            keysym = held;
        else
            _pressedKeysyms.Add(e.Key, keysym);
        e.Handled = true;
        await _viewModel.SendKeyAsync(1, keysym);
    }

    private async void OnKeyUp(object? sender, KeyEventArgs e)
    {
        if (_viewModel == null)
            return;
        if (_pressedKeysyms.Remove(e.Key, out var keysym))
        {
            e.Handled = true;
            await _viewModel.SendKeyAsync(0, keysym);
        }
    }

    private (ushort x, ushort y)? ToFramePosition(PointerEventArgs e, bool clamp = false)
    {
        var frame = _viewModel?.Frame;
        if (frame == null || frame.Width == 0 || frame.Height == 0)
            return null;
        var size = Viewport.Bounds.Size;
        var scale = Math.Min(size.Width / frame.Width, size.Height / frame.Height);
        if (scale <= 0)
            return null;
        var point = e.GetPosition(Viewport);
        var x = (point.X - (size.Width - frame.Width * scale) / 2) / scale;
        var y = (point.Y - (size.Height - frame.Height * scale) / 2) / scale;
        if (!clamp && (x < 0 || y < 0 || x >= frame.Width || y >= frame.Height))
            return null;
        return ((ushort)Math.Clamp(x, 0, frame.Width - 1), (ushort)Math.Clamp(y, 0, frame.Height - 1));
    }

    private async void OnPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (_viewModel == null || _viewModel.Frame == null)
            return;
        if (ToFramePosition(e, _buttons != 0) is not { } position)
            return;
        (_lastX, _lastY) = position;
        var button = e.GetCurrentPoint(Viewport).Properties.PointerUpdateKind;
        _buttons = button switch
        {
            PointerUpdateKind.LeftButtonPressed => (byte)(_buttons | 1),
            PointerUpdateKind.MiddleButtonPressed => (byte)(_buttons | 4),
            PointerUpdateKind.RightButtonPressed => (byte)(_buttons | 2),
            _ => _buttons,
        };
        Viewport.Focus();
        e.Pointer.Capture(Viewport);
        e.Handled = true;
        await _viewModel.SendPointerAsync(_buttons, _lastX, _lastY);
    }

    private async void OnPointerMoved(object? sender, PointerEventArgs e)
    {
        if (_viewModel == null || _viewModel.Frame == null)
            return;
        if (ToFramePosition(e, _buttons != 0) is not { } position)
            return;
        (_lastX, _lastY) = position;
        await _viewModel.SendPointerAsync(_buttons, _lastX, _lastY);
    }

    private async void OnPointerReleased(object? sender, PointerReleasedEventArgs e)
    {
        if (_viewModel == null)
            return;
        if (ToFramePosition(e, true) is { } position)
            (_lastX, _lastY) = position;
        var button = e.GetCurrentPoint(Viewport).Properties.PointerUpdateKind;
        _buttons = button switch
        {
            PointerUpdateKind.LeftButtonReleased => (byte)(_buttons & ~1),
            PointerUpdateKind.MiddleButtonReleased => (byte)(_buttons & ~4),
            PointerUpdateKind.RightButtonReleased => (byte)(_buttons & ~2),
            _ => (byte)0,
        };
        e.Handled = true;
        if (_buttons == 0)
            e.Pointer.Capture(null);
        await _viewModel.SendPointerAsync(_buttons, _lastX, _lastY);
    }

    private async void OnPointerWheelChanged(object? sender, PointerWheelEventArgs e)
    {
        if (_viewModel == null || e.Delta.Y == 0 || ToFramePosition(e) is not { } point) return;
        e.Handled = true;
        await _viewModel.SendScrollAsync(_buttons, point.x, point.y, (sbyte)Math.Sign(e.Delta.Y));
    }

    private async void OnPointerCaptureLost(object? sender, PointerCaptureLostEventArgs e)
    {
        if (_buttons == 0 || _viewModel == null)
            return;
        _buttons = 0;
        await _viewModel.SendPointerAsync(0, _lastX, _lastY);
    }

    /// <summary>焦点丢失释放按下的键与鼠标键，避免后台标签继续发送输入。</summary>
    private async void OnLostFocus(object? sender, RoutedEventArgs e)
    {
        if (_viewModel == null)
            return;
        var keys = _pressedKeysyms.Values.ToArray();
        _pressedKeysyms.Clear();
        var buttons = _buttons;
        _buttons = 0;
        await _viewModel.ReleaseAllAsync(keys, buttons, _lastX, _lastY);
    }
}

internal static class KeyMapping
{
    // X11 keysym 子集；按物理键映射，覆盖常见键，未映射返回 0；不处理 IME 组合文本。
    public static uint ToKeysym(KeyEventArgs e)
    {
        if (!string.IsNullOrEmpty(e.KeySymbol) && e.KeySymbol.Length == 1)
        {
            var c = e.KeySymbol[0];
            if (c >= 0x20 && c < 0x7f)
                return c;
        }

        return e.Key switch
        {
            Key.Back => 0xFF08,
            Key.Tab => 0xFF09,
            Key.Return or Key.Enter => 0xFF0D,
            Key.Escape => 0xFF1B,
            Key.Insert => 0xFF63,
            Key.Delete => 0xFFFF,
            Key.Home => 0xFF50,
            Key.Left => 0xFF51,
            Key.Up => 0xFF52,
            Key.Right => 0xFF53,
            Key.Down => 0xFF54,
            Key.PageUp => 0xFF55,
            Key.PageDown => 0xFF56,
            Key.End => 0xFF57,
            Key.F1 => 0xFFBE,
            Key.F2 => 0xFFBF,
            Key.F3 => 0xFFC0,
            Key.F4 => 0xFFC1,
            Key.F5 => 0xFFC2,
            Key.F6 => 0xFFC3,
            Key.F7 => 0xFFC4,
            Key.F8 => 0xFFC5,
            Key.F9 => 0xFFC6,
            Key.F10 => 0xFFC7,
            Key.F11 => 0xFFC8,
            Key.F12 => 0xFFC9,
            Key.Space => 0x20,
            Key.LeftShift => 0xFFE1,
            Key.RightShift => 0xFFE2,
            Key.LeftCtrl => 0xFFE3,
            Key.RightCtrl => 0xFFE4,
            Key.LeftAlt => 0xFFE9,
            Key.RightAlt => 0xFFEA,
            Key.LWin => 0xFFEB,
            Key.RWin => 0xFFEC,
            _ => MapAlphaDigit(e.Key),
        };
    }

    private static uint MapAlphaDigit(Key key)
    {
        var name = key.ToString();
        if (name.Length == 1)
        {
            var c = name[0];
            if (c is >= 'A' and <= 'Z')
                return (uint)(c - 'A' + 'a');
            if (c is >= '0' and <= '9')
                return (uint)c;
        }

        return 0;
    }
}
