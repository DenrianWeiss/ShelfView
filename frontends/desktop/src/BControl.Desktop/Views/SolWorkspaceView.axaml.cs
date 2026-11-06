using System.ComponentModel;
using Avalonia.Controls;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using BControl.Desktop.ViewModels;

namespace BControl.Desktop.Views;
public partial class SolWorkspaceView : UserControl
{
    private SolWorkspaceViewModel? _viewModel;
    public SolWorkspaceView()
    {
        InitializeComponent();
        Terminal.InputFailed += error => { if (_viewModel != null) _viewModel.Status = error.Message; };
        BuildContextMenu();
        AddHandler(KeysMenuActions.Event, async (_, args) =>
        {
            if (args.Action == "copy")
                await Terminal.CopyAsync();
            else if (args.Action == "paste")
                await PasteAsync(false);
            else if (args.Action == "slow")
                await PasteAsync(true);
            else if (args.Action == "cancel")
                _viewModel?.CancelPaste();
            args.Handled = true;
        });
        DataContextChanged += (_, _) =>
        {
            if (_viewModel != null)
                _viewModel.PropertyChanged -= OnPropertyChanged;
            _viewModel = DataContext as SolWorkspaceViewModel;
            if (_viewModel != null)
            {
                _viewModel.PropertyChanged += OnPropertyChanged;
                _viewModel.ApplicationCursor = () => Terminal.Terminal?.ApplicationCursorKeys == true;
                _viewModel.BracketedPaste = () => Terminal.Terminal?.BracketedPasteMode == true;
            }

            Attach();
        };
        DetachedFromVisualTree += (_, _) =>
        {
            Core.Localization.Loc.Instance.LanguageChanged -= BuildContextMenu;
            Terminal.Connection = null;
            if (_viewModel != null)
                _viewModel.PropertyChanged -= OnPropertyChanged;
        };
        AttachedToVisualTree += (_, _) =>
        {
            Core.Localization.Loc.Instance.LanguageChanged += BuildContextMenu;
            BuildContextMenu();
            if (_viewModel != null)
            {
                _viewModel.PropertyChanged -= OnPropertyChanged;
                _viewModel.PropertyChanged += OnPropertyChanged;
            }

            Attach();
        };
    }

    private void BuildContextMenu()
    {
        var menu = new ContextMenu();
        void Add(string key, EventHandler<RoutedEventArgs> action)
        {
            var item = new MenuItem
            {
                Header = Core.Localization.Loc.T(key)
            };
            item.Click += action;
            menu.Items.Add(item);
        }

        Add("sol.copy", OnCopy);
        Add("sol.paste", OnPaste);
        Add("sol.slowPaste", OnSlowPaste);
        Add("sol.cancelPaste", (_, _) => _viewModel?.CancelPaste());
        Terminal.ContextMenu = menu;
    }

    private void OnPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(SolWorkspaceViewModel.Connection))
            Attach();
    }

    private void Attach() => Terminal.Connection = _viewModel?.Connection;

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

    private void OnCancelPaste(object? sender, RoutedEventArgs e) => _viewModel?.CancelPaste();
    private async void OnCopy(object? sender, RoutedEventArgs e) => await Terminal.CopyAsync();
    private async void OnPaste(object? sender, RoutedEventArgs e) => await PasteAsync(false);
    private async void OnSlowPaste(object? sender, RoutedEventArgs e) => await PasteAsync(true);
    private async Task PasteAsync(bool slow)
    {
        if (_viewModel?.IsConnected != true || TopLevel.GetTopLevel(this)?.Clipboard is not { } clipboard)
            return;
        var text = await clipboard.TryGetTextAsync();
        if (text != null)
            await _viewModel.PasteAsync(text, slow);
    }
}
