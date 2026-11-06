namespace BControl.Core.Media;
public sealed class MediaStartupException : IOException
{
    public ILocalMediaSession Session { get; }

    public MediaStartupException(ILocalMediaSession session, Exception cause) : base(cause.Message, cause) => Session = session;
}
