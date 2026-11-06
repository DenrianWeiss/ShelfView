using Avalonia.Controls;
using BControl.Core.Input;
using BControl.Core.Localization;
using BControl.Desktop.Services;
using BControl.Desktop.ViewModels;

namespace BControl.Desktop.Views;
public sealed class RemoteKeysMenu : Menu
{
    public RemoteKeysMenu()
    {
        AttachedToVisualTree += (_, _) =>
        {
            Loc.Instance.LanguageChanged += Build;
            Build();
        };
        DetachedFromVisualTree += (_, _) => Loc.Instance.LanguageChanged -= Build;
        DataContextChanged += (_, _) => Build();
    }

    private void Build()
    {
        var sol = DataContext is SolWorkspaceViewModel;
        var root = new MenuItem
        {
            Header = Loc.T("keys.send")
        };
        void Add(MenuItem parent, KeyCombination combination)
        {
            var item = new MenuItem
            {
                Header = combination.Label,
                IsEnabled = !sol || RemoteKeys.TerminalBytes(combination.Keys) != null
            };
            item.Click += async (_, _) =>
            {
                if (DataContext is KvmWorkspaceViewModel kvm)
                    await kvm.SendChordAsync(combination.Keys);
                else if (DataContext is SolWorkspaceViewModel terminal)
                    await terminal.SendKeysAsync(combination.Keys);
            };
            parent.Items.Add(item);
        }

        foreach (var preset in sol ? Enumerable.Range(0, 26).Select(i => new KeyCombination("", [0xffe3, (uint)('a' + i)])) : RemoteKeys.Presets)
            Add(root, preset);
        foreach (var(key, items)in new[]
        {
            ("keys.special", RemoteKeys.Special),
            ("keys.functions", RemoteKeys.Functions)
        }

        )
        {
            var parent = new MenuItem
            {
                Header = Loc.T(key)
            };
            foreach (var item in items)
                Add(parent, item);
            root.Items.Add(parent);
        }

        var custom = new MenuItem
        {
            Header = Loc.T("keys.custom")
        };
        foreach (var item in new CustomKeysStore(sol).Items)
            Add(custom, item);
        root.Items.Add(custom);
        var manage = new MenuItem
        {
            Header = Loc.T("keys.manage")
        };
        manage.Click += async (_, _) =>
        {
            if (TopLevel.GetTopLevel(this)is Window owner)
                await new CustomKeysWindow(sol).ShowDialog(owner);
            Build();
        };
        root.Items.Add(manage);
        Items.Clear();
        Items.Add(root);
    }
}
