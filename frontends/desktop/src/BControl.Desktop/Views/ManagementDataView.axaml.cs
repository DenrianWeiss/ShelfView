using Avalonia.Controls;
using Avalonia.Interactivity;
using BControl.Desktop.ViewModels;

namespace BControl.Desktop.Views;
public partial class ManagementDataView : UserControl
{
    public ManagementDataView() => InitializeComponent();
    private async void OnSwitch(object? sender, RoutedEventArgs e)
    {
        if (DataContext is ManagementDataViewModel model && sender is Button { Tag: Core.Redfish.ManagementSwitch item } && TopLevel.GetTopLevel(this)is Window owner)
            await model.ApplySwitchAsync(item, text => ConfirmDialog.ShowAsync(owner, text));
    }

    private async void OnRefresh(object? sender, RoutedEventArgs e)
    {
        if (DataContext is ManagementDataViewModel model)
            await model.LoadAsync(refresh: true);
    }
}
