using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using Avalonia.Media;
using BControl.Core.Localization;
using BControl.Core.Storage;
using BControl.Desktop.Services;

namespace BControl.Desktop.Views;

public sealed class VaultConflictsWindow : Window
{
    private readonly ServerStore _store;
    private readonly Func<Window, Task<bool>> _prepare;
    private readonly Func<string, string> _describe;
    private readonly ComboBox _groups = new() { MinWidth = 180 };
    private readonly StackPanel _rows = new() { Spacing = 16 };
    private readonly TextBlock _status = new() { TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock _mode = new() { TextWrapping = TextWrapping.Wrap };
    private readonly Button _apply = new() { Content = Loc.T("vault.apply"), IsEnabled = false };
    private readonly Button _cancel = new() { Content = Loc.T("common.close") };
    private readonly Button _reload = new() { Content = Loc.T("common.refresh") };
    private readonly CancellationTokenSource _lifetime = new();
    private VaultConflictReview? _review;
    private IReadOnlyList<string> _ids = [];
    private readonly Dictionary<uint, VaultMergeChoice> _choices = [];
    private VaultMergeChoice? _version;
    private int _generation;
    private bool _applying, _prepared, _loadingGroups;
    public bool IsApplying => _applying;
    public bool Applied { get; private set; }
    public bool CleanupComplete { get; private set; }
    public VaultConflictsWindow(ServerStore store, Func<Window, Task<bool>> prepare, Func<string, string>? describe = null)
    {
        _store = store; _prepare = prepare; _describe = describe ?? (_ => Loc.T("vault.record"));
        Title = Loc.T("vault.conflicts"); Width = 720; Height = 560; MinWidth = 520; MinHeight = 360;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var top = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Children = { _groups, _reload } };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, HorizontalAlignment = HorizontalAlignment.Right, Children = { _cancel, _apply } };
        var content = new Grid { RowDefinitions = new("Auto,Auto,*,Auto,Auto"), Margin = new Thickness(20), RowSpacing = 12 };
        var scroll = new ScrollViewer { Content = _rows, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
        content.Children.Add(top); content.Children.Add(_mode); Grid.SetRow(_mode, 1);
        content.Children.Add(scroll); Grid.SetRow(scroll, 2); content.Children.Add(_status); Grid.SetRow(_status, 3);
        content.Children.Add(buttons); Grid.SetRow(buttons, 4); Content = content;
        _groups.SelectionChanged += async (_, _) => { if (!_applying && !_loadingGroups) await LoadReviewAsync(); };
        _reload.Click += async (_, _) => await LoadGroupsAsync(); _cancel.Click += (_, _) => Close();
        _apply.Click += async (_, _) => await ApplyAsync();
        Opened += async (_, _) => await LoadGroupsAsync();
        Closing += (_, args) => { if (_applying) args.Cancel = true; };
        Closed += (_, _) => { ++_generation; _lifetime.Cancel(); _review?.Dispose(); _review = null; };
    }
    private async Task LoadGroupsAsync()
    {
        if (_loadingGroups || _applying) return;
        _loadingGroups = true; ++_generation;
        _review?.Dispose(); _review = null; _choices.Clear(); _version = null; _ids = [];
        _rows.Children.Clear(); _mode.Text = ""; _status.Text = "";
        _reload.IsEnabled = false; _groups.IsEnabled = false; UpdateApply();
        try {
            _ids = await _store.ListConflictsAsync(_lifetime.Token);
            if (_lifetime.IsCancellationRequested) return;
            _groups.ItemsSource = _ids.Select((_, i) => Loc.F("vault.conflictNumber", ("number", i + 1))).ToArray();
            if (_ids.Count > 0) _groups.SelectedIndex = 0;
            else { _rows.Children.Clear(); _mode.Text = ""; _status.Text = Loc.T("vault.noConflicts"); _apply.IsEnabled = false; }
        } catch (OperationCanceledException) { }
        catch (Exception error) { _status.Text = VaultMessages.Describe(error); }
        finally { _loadingGroups = false; _reload.IsEnabled = true; _groups.IsEnabled = true; UpdateApply(); }
        if (!_lifetime.IsCancellationRequested && _ids.Count != 0) await LoadReviewAsync();
    }
    private async Task LoadReviewAsync()
    {
        var generation = ++_generation;
        _review?.Dispose(); _review = null; _choices.Clear(); _version = null; _rows.Children.Clear(); _apply.IsEnabled = false; _status.Text = "";
        var index = _groups.SelectedIndex;
        if (index < 0 || index >= _ids.Count) return;
        try {
            var review = await _store.OpenConflictAsync(_ids[index], _lifetime.Token);
            if (generation != _generation || _lifetime.IsCancellationRequested) { review.Dispose(); return; }
            _review = review; _mode.Text = Loc.T(review.FieldChoices ? "vault.chooseFields" : "vault.chooseVersion");
            if (review.FieldChoices) {
                for (uint i = 0; i < review.Fields.Count; ++i) {
                    var field = review.Fields[(int)i]; var choiceIndex = i;
                    var key = "vault.field." + field.Field; var label = Loc.T(key);
                    if (label == key) label = Loc.T(string.IsNullOrEmpty(field.Field) ? "vault.record" : "vault.valueLabel");
                    var row = new StackPanel { Spacing = 6 };
                    row.Children.Add(new TextBlock { Text = _describe(field.Record) + " · " + label, FontWeight = FontWeight.SemiBold, TextWrapping = TextWrapping.Wrap });
                    row.Children.Add(Choice("field-" + i, Loc.T("vault.localVersion") + ": " + field.Local.Display, () => _choices[choiceIndex] = VaultMergeChoice.Local));
                    row.Children.Add(Choice("field-" + i, Loc.T("vault.currentVersion") + ": " + field.Remote.Display, () => _choices[choiceIndex] = VaultMergeChoice.Remote));
                    _rows.Children.Add(row);
                }
            } else {
                _rows.Children.Add(Choice("version", Loc.T("vault.localVersion"), () => _version = VaultMergeChoice.Local));
                _rows.Children.Add(Choice("version", Loc.T("vault.currentVersion"), () => _version = VaultMergeChoice.Remote));
            }
            UpdateApply();
        } catch (OperationCanceledException) { }
        catch (Exception error) { if (generation == _generation) _status.Text = VaultMessages.Describe(error); }
    }
    private RadioButton Choice(string group, string label, Action selected)
    {
        var button = new RadioButton { GroupName = group, Content = new TextBlock { Text = label, TextWrapping = TextWrapping.Wrap } };
        button.PropertyChanged += (_, args) => { if (args.Property == ToggleButton.IsCheckedProperty && button.IsChecked == true) { selected(); UpdateApply(); } };
        return button;
    }
    private void UpdateApply() => _apply.IsEnabled = !_applying && !_loadingGroups && _review is { } review && (review.FieldChoices ? _choices.Count == review.Fields.Count : _version != null);
    private async Task ApplyAsync()
    {
        if (_applying || _review == null) return;
        _applying = true; UpdateApply(); _cancel.IsEnabled = false; _groups.IsEnabled = false; _reload.IsEnabled = false; _rows.IsEnabled = false;
        try {
            if (!_prepared) {
                try { if (!await _prepare(this)) return; _prepared = true; }
                catch { _status.Text = Loc.T("vault.connectionsNotClosed"); return; }
            }
            CleanupComplete = await _store.ApplyConflictAsync(_review, _choices, _version, _lifetime.Token);
            Applied = true;
        }
        catch (Exception error) {
            var message = error is VaultChangedException ? Loc.T("vault.reviewChanged") : VaultMessages.Describe(error);
            await LoadReviewAsync(); _status.Text = message;
        }
        finally { _applying = false; _cancel.IsEnabled = true; _groups.IsEnabled = true; _reload.IsEnabled = true; _rows.IsEnabled = true; UpdateApply(); }
        if (Applied) Close();
    }
}
