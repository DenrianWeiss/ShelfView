using System.Runtime.InteropServices;
using BControl.Core.Media;
using BControl.Core.Native;

namespace BControl.Core.Kvm;
public sealed class RecoveringConsoleSession : IKvmSession, ILocalMediaConsole
{
    private readonly Func<Task<IKvmSession>> _connect;
    private readonly Func<bool> _mediaActive;
    private readonly SemaphoreSlim _gate = new(1);
    private IKvmSession? _current;
    private IntPtr _recovery;
    private volatile bool _closed, _recovering;
    private string? _error;
    public bool IsConnected => !_closed && (_recovering || _current?.IsConnected == true);
    public KvmFrame? LatestFrame => _current?.LatestFrame;
    public FeatureDetection LocalMediaDetection => !_closed && !_recovering && _current is ILocalMediaConsole media
        ? media.LocalMediaDetection : FeatureDetection.FromProbe(DeviceFeature.LocalMedia);
    public bool LocalMediaAvailable => LocalMediaDetection.CanAttempt;

    public event Action<KvmFrame>? FrameReceived;
    public event Action<string>? Failed;
    public event Action? Closed;
    private RecoveringConsoleSession(Func<Task<IKvmSession>> connect, Func<bool> mediaActive)
    {
        _connect = connect;
        _mediaActive = mediaActive;
    }

    public static async Task<RecoveringConsoleSession> ConnectAsync(Func<Task<IKvmSession>> connect, Func<bool> mediaActive)
    {
        var owner = new RecoveringConsoleSession(connect, mediaActive);
        try
        {
            var started = Now;
            BcServiceProfile? expected = null;
            while (true)
            {
                try
                {
                    var session = await connect();
                    if (expected is { } profile && (session is not IConsoleProtocol candidate || candidate.Profile.Family != profile.Family || candidate.Profile.Variant != profile.Variant))
                    {
                        await session.DisposeAsync();
                        throw new BcException(Bc.Unsupported, Bc.StatusText(Bc.Unsupported));
                    }

                    owner.Attach(session);
                    return owner;
                }
                catch (Exception ex)when (ex.Data[ConsoleAttempt.Key] is ConsoleAttempt)
                {
                    var attempt = (ConsoleAttempt)ex.Data[ConsoleAttempt.Key]!;
                    if (owner._recovery == IntPtr.Zero)
                    {
                        var profile = attempt.Profile;
                        if (RecoveryNative.bc_console_recovery_op_create(ref profile, started, 60000, out owner._recovery) != Bc.Ok)
                            throw;
                    }

                    var failure = attempt.Failure;
                    if (RecoveryNative.bc_console_recovery_op_failed(owner._recovery, owner.Attempt, ref failure, 1, IntPtr.Zero, mediaActive() ? 1 : 0, Now, out var action) != Bc.Ok || action == 0)
                        throw;
                    if (RecoveryNative.bc_console_recovery_op_resume(owner._recovery, owner.Attempt, attempt.Cleaned ? 1 : 0, Now, out var next) != Bc.Ok)
                        throw;
                    expected = next;
                }
            }
        }
        catch
        {
            await owner.DisposeAsync();
            throw;
        }
    }

    private uint Attempt => Marshal.PtrToStructure<BcRecoveryView>(RecoveryNative.bc_console_recovery_op_view_get(_recovery)).Attempt;
    private static ulong Now => (ulong)Environment.TickCount64;

    private void Attach(IKvmSession session)
    {
        _current = session;
        if(!session.IsConnected)throw new IOException(Bc.StatusText(Bc.IoError));
        _error = null;
        session.FrameReceived += frame =>
        {
            if (ReferenceEquals(_current, session))
                FrameReceived?.Invoke(frame);
        };
        session.Failed += reason =>
        {
            if (ReferenceEquals(_current, session))
                _error = reason;
        };
        session.Closed += () =>
        {
            if (!_closed && ReferenceEquals(_current, session))
                _ = Task.Run(() => RecoverAsync(session));
        };
        if (session is IConsoleProtocol protocol)
        {
            if (_recovery == IntPtr.Zero)
            {
                var profile = protocol.Profile;
                Bc.Check(RecoveryNative.bc_console_recovery_op_create(ref profile, Now, 20000, out _recovery), "kvm.title");
            }

            Bc.Check(RecoveryNative.bc_console_recovery_op_succeeded(_recovery, Attempt, Now), "kvm.title");
        }
    }

    private async Task RecoverAsync(IKvmSession session)
    {
        await _gate.WaitAsync();
        try
        {
            if (_closed || !ReferenceEquals(session, _current))
                return;
            if (_recovery == IntPtr.Zero || session is not IConsoleProtocol protocol)
            {
                Stop();
                return;
            }

            var incident = protocol.Failure;
            if (incident.Status == Bc.Ok)
            {
                incident.StructSize = (uint)Marshal.SizeOf<BcConsoleFailure>();
                incident.Status = Bc.IoError;
                incident.Phase = 4;
                incident.Service = 1;
                incident.Family = protocol.Profile.Family;
                incident.Profile = protocol.Profile.Variant;
            }

            var status = RecoveryNative.bc_console_recovery_op_disconnected(_recovery, Attempt, ref incident, 1, IntPtr.Zero, _mediaActive() ? 1 : 0, Now, 20000, out var action);
            if (status != Bc.Ok || action == 0)
            {
                Stop();
                return;
            }

            _recovering = true;
            var attempt = Attempt;
            await session.DisposeAsync();
            status = RecoveryNative.bc_console_recovery_op_resume(_recovery, attempt, protocol.CleanupSucceeded ? 1 : 0, Now, out var next);
            if (status != Bc.Ok)
            {
                Stop();
                return;
            }

            IKvmSession? replacement = null;
            try
            {
                // A new HTTP owner may refresh a ticket, but runtime recovery never switches protocol families or wire layouts.
                replacement = await _connect();
                if (replacement is not IConsoleProtocol candidate || candidate.Profile.Family != next.Family || candidate.Profile.Variant != next.Variant)
                    throw new BcException(Bc.Unsupported, Bc.StatusText(Bc.Unsupported));
                Attach(replacement);
                replacement = null;
            }
            catch (Exception ex)
            {
                if (replacement != null)
                    await replacement.DisposeAsync();
                _error = ex.Message;
                Stop();
            }
            finally
            {
                _recovering = false;
            }
        }
        catch (Exception ex)
        {
            _error = ex.Message;
            Stop();
        }
        finally
        {
            _gate.Release();
        }
    }

    private void Stop()
    {
        _closed = true;
        _recovering = false;
        Failed?.Invoke(_error ?? Bc.StatusText(Bc.IoError));
        Closed?.Invoke();
    }

    public FeatureDetection KvmDetection => _current?.KvmDetection
        ?? FeatureDetection.FromProbe(DeviceFeature.Kvm);
    public bool SupportsScroll => _current?.SupportsScroll == true;
    public Task SendScrollAsync(byte buttons, ushort x, ushort y, sbyte wheel)
    {
        var current = _current;
        return !_closed && !_recovering && current?.IsConnected == true
            ? current.SendScrollAsync(buttons, x, y, wheel) : Task.CompletedTask;
    }
    public Task SendChordAsync(IReadOnlyList<uint> keys) {
        var current = _current;
        return !_closed && !_recovering && current?.IsConnected == true
            ? current.SendChordAsync(keys) : Task.CompletedTask;
    }
    public Task SendKeyAsync(int down, uint keysym) => !_closed && !_recovering && _current?.IsConnected == true ? _current.SendKeyAsync(down, keysym) : Task.CompletedTask;
    public Task SendPointerAsync(byte buttons, ushort x, ushort y) => !_closed && !_recovering && _current?.IsConnected == true ? _current.SendPointerAsync(buttons, x, y) : Task.CompletedTask;
    public Task<ILocalMediaSession> MountIsoAsync(string path) => _current is ILocalMediaConsole console ? console.MountIsoAsync(path) : Task.FromException<ILocalMediaSession>(new NotSupportedException());
    public async ValueTask DisposeAsync()
    {
        _closed = true;
        await _gate.WaitAsync();
        try
        {
            if (_current != null)
                await _current.DisposeAsync();
            _current = null;
            if (_recovery != IntPtr.Zero)
            {
                RecoveryNative.bc_console_recovery_op_destroy(_recovery);
                _recovery = IntPtr.Zero;
            }
        }
        finally
        {
            _gate.Release();
        }
    }
}
