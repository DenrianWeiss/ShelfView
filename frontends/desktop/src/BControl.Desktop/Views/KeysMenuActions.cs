using Avalonia.Interactivity;

namespace BControl.Desktop.Views;
public sealed class KeysMenuActionEventArgs(string action) : RoutedEventArgs(KeysMenuActions.Event)
{
    public string Action { get; } = action;
}

public static class KeysMenuActions
{
    public static readonly RoutedEvent<KeysMenuActionEventArgs> Event = RoutedEvent.Register<SolWorkspaceView, KeysMenuActionEventArgs>("SolAction", RoutingStrategies.Bubble);
}
