using System.Windows.Input;

namespace BControl.Desktop.ViewModels;

public sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<object?, Task> _execute;
    private readonly Predicate<object?>? _canExecute;
    private volatile bool _running;

    public AsyncRelayCommand(Func<object?, Task> execute, Predicate<object?>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) => !_running && (_canExecute?.Invoke(parameter) ?? true);

    public async void Execute(object? parameter)
    {
        _running = true;
        Changed?.Invoke(this, EventArgs.Empty);
        try { await _execute(parameter); }
        finally
        {
            _running = false;
            Changed?.Invoke(this, EventArgs.Empty);
        }
    }

    public event EventHandler? CanExecuteChanged
    {
        add { Changed += value; }
        remove { Changed -= value; }
    }

    public event EventHandler? Changed;
}
