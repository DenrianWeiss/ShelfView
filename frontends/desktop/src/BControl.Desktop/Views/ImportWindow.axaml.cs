using Avalonia.Controls;
using Avalonia.Interactivity;

namespace BControl.Desktop.Views;
public partial class ImportWindow : Window
{
    public ImportWindow() => InitializeComponent();
    private void OnCancel(object? sender, RoutedEventArgs e) => Close((bool? )null);
    private void OnImport(object? sender, RoutedEventArgs e) => Close((bool? )(UpdateNames.IsChecked == true));
}
