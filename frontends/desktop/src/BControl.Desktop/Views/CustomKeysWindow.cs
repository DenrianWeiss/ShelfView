using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Layout;
using BControl.Core.Input;
using BControl.Core.Localization;
using BControl.Desktop.Services;

namespace BControl.Desktop.Views;
public sealed class CustomKeysWindow : Window
{
    private readonly CustomKeysStore _store;
    private readonly List<KeyCombination> _items;
    private readonly ListBox _list = new()
    {
        Height = 140
    };
    private readonly TextBox _name = new(), _codes = new(), _capture = new()
    {
        IsReadOnly = true
    };
    private readonly TextBlock _status = new()
    {
        TextWrapping = Avalonia.Media.TextWrapping.Wrap
    };
    private readonly bool _sol;
    private readonly Dictionary<Key, uint> _held = new();
    private int _peak;
    public CustomKeysWindow(bool sol)
    {
        _sol = sol;
        _store = new(sol);
        _items = _store.Items.ToList();
        Title = Loc.T("keys.manage");
        Width = 470;
        SizeToContent = SizeToContent.Height;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var add = new Button
        {
            Content = Loc.T("keys.add")
        };
        add.Click += (_, _) =>
        {
            _list.SelectedIndex = -1;
            _name.Text = "";
            _codes.Text = "";
        };
        var remove = new Button
        {
            Content = Loc.T("common.delete")
        };
        remove.Click += (_, _) =>
        {
            if (_list.SelectedIndex >= 0)
            {
                _items.RemoveAt(_list.SelectedIndex);
                Refresh();
            }
        };
        var save = new Button
        {
            Content = Loc.T("keys.save")
        };
        save.Click += (_, _) => Save();
        var close = new Button
        {
            Content = Loc.T("common.close")
        };
        close.Click += (_, _) => Close();
        _list.SelectionChanged += (_, _) =>
        {
            if (_list.SelectedItem is KeyCombination item)
            {
                _name.Text = item.Name;
                _codes.Text = string.Join(" ", item.Keys.Select(key => $"0x{key:X}"));
            }
        };
        _capture.LostFocus += (_, _) =>
        {
            _held.Clear();
            _peak = 0;
        };
        _capture.AddHandler(KeyUpEvent, (_, e) =>
        {
            _held.Remove(e.Key);
            if (_held.Count == 0)
                _peak = 0;
            e.Handled = true;
        }, Avalonia.Interactivity.RoutingStrategies.Tunnel);
        _capture.PlaceholderText = Loc.T("keys.press");
        _capture.AddHandler(KeyDownEvent, OnCapture, Avalonia.Interactivity.RoutingStrategies.Tunnel);
        Content = new StackPanel
        {
            Margin = new Thickness(20),
            Spacing = 10,
            Children =
            {
                _list,
                new StackPanel
                {
                    Orientation = Orientation.Horizontal,
                    Spacing = 8,
                    Children =
                    {
                        add,
                        remove
                    }
                },
                new TextBlock
                {
                    Text = Loc.T("keys.name")
                },
                _name,
                new TextBlock
                {
                    Text = Loc.T("keys.captureHint"),
                    TextWrapping = Avalonia.Media.TextWrapping.Wrap
                },
                _capture,
                new TextBlock
                {
                    Text = Loc.T("keys.codeHint"),
                    TextWrapping = Avalonia.Media.TextWrapping.Wrap
                },
                _codes,
                _status,
                new StackPanel
                {
                    Orientation = Orientation.Horizontal,
                    Spacing = 8,
                    HorizontalAlignment = HorizontalAlignment.Right,
                    Children =
                    {
                        close,
                        save
                    }
                }
            }
        };
        Refresh();
    }

    private void Refresh()
    {
        _list.ItemsSource = null;
        _list.ItemsSource = _items.ToArray();
    }

    private void OnCapture(object? sender, KeyEventArgs e)
    {
        var key = KeyMapping.ToKeysym(e);
        if (key != 0)
            _held.TryAdd(e.Key, key);
        var keys = _held.Values.ToList();
        if (e.KeyModifiers.HasFlag(KeyModifiers.Control) && !keys.Any(k => k is 0xffe3 or 0xffe4))
            keys.Add(0xffe3);
        if (e.KeyModifiers.HasFlag(KeyModifiers.Shift) && !keys.Any(k => k is 0xffe1 or 0xffe2))
            keys.Add(0xffe1);
        if (e.KeyModifiers.HasFlag(KeyModifiers.Alt) && !keys.Any(k => k is 0xffe9 or 0xffea))
            keys.Add(0xffe9);
        if (e.KeyModifiers.HasFlag(KeyModifiers.Meta) && !keys.Any(k => k is 0xffeb or 0xffec))
            keys.Add(0xffeb);
        var ordered = RemoteKeys.Order(keys);
        if (ordered != null && ordered.Length >= _peak)
        {
            _peak = ordered.Length;
            _codes.Text = string.Join(" ", ordered.Select(k => $"0x{k:X}"));
            _capture.Text = string.Join("+", ordered.Select(RemoteKeys.Label));
        }

        e.Handled = true;
    }

    private void Save()
    {
        var keys = RemoteKeys.Parse(_codes.Text ?? "");
        if (keys == null || (_name.Text?.Length ?? 0) > 48)
        {
            _status.Text = Loc.T("keys.invalid");
            return;
        }

        if (_sol && RemoteKeys.TerminalBytes(keys) == null)
        {
            _status.Text = Loc.T("keys.solUnsupported");
            return;
        }

        var item = new KeyCombination(_name.Text?.Trim() ?? "", keys);
        var index = _list.SelectedIndex;
        var next = _items.ToList();
        if (index >= 0)
            next[index] = item;
        else
            next.Add(item);
        try
        {
            _store.Save(next);
            _items.Clear();
            _items.AddRange(next);
            Refresh();
            _status.Text = "";
        }
        catch
        {
            _status.Text = Loc.T("keys.saveFailed");
        }
    }
}
