using Avalonia.Controls;
using Avalonia.Interactivity;
using BControl.Desktop.ViewModels;

namespace BControl.Desktop.Views;
public partial class PowerControlView : UserControl
{
    public PowerControlView() => InitializeComponent();
    private async void OnPower(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not ServerControlViewModel model || TopLevel.GetTopLevel(this) is not Window owner) return;
        try { await model.ApplyPowerAsync(message => ConfirmDialog.ShowAsync(owner, message)); }
        catch (Exception error) { model.SetFailure(error); }
    }
}
