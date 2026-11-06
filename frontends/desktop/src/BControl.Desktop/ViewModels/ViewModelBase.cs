using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace BControl.Desktop.ViewModels;

public abstract class ViewModelBase : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        return true;
    }

    protected void RaiseChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public enum WorkspaceFeature { Kvm, Sol, Media }

/// <summary>(server_id, feature, resource_id) 唯一标签键。</summary>
public sealed record WorkspaceKey(string ServerId, WorkspaceFeature Feature, string ResourceId = "")
{
    public string TabId => $"{ServerId}:{Feature}:{ResourceId}";
    public override string ToString() => TabId;
}

public sealed class WorkspaceTab : ViewModelBase
{
    private readonly Func<string> _title;

    public WorkspaceKey Key { get; }
    public string Title => _title();
    public bool CanClose => true;

    private object? _content;
    public object? Content
    {
        get => _content;
        set => SetProperty(ref _content, value);
    }

    private bool _isVisible;
    public bool IsVisible
    {
        get => _isVisible;
        set => SetProperty(ref _isVisible, value);
    }

    public WorkspaceTab(WorkspaceKey key, string title, object content) : this(key, () => title, content) { }

    public WorkspaceTab(WorkspaceKey key, Func<string> title, object content)
    {
        Key = key;
        _title = title;
        _content = content;
    }

    /// <summary>语言切换后让标题绑定重新求值。</summary>
    public void RefreshLanguage() => RefreshTitle();
    internal void RefreshTitle() => RaiseChanged(nameof(Title));
}
