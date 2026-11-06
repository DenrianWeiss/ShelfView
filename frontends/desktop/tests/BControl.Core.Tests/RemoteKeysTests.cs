using System.Text;
using BControl.Core.Input;

namespace BControl.Core.Tests;
public sealed class RemoteKeysTests
{
    [Theory]
    [InlineData("0xffe3 97", "\u0001")]
    [InlineData("0xffe9 97", "\u001ba")]
    [InlineData("0xffe1 0xff52", "\u001b[1;2A")]
    [InlineData("0xffe3 0xffff", "\u001b[3;5~")]
    [InlineData("0xffe1 0xff09", "\u001b[Z")]
    [InlineData("0xffc9", "\u001b[24~")]
    public void TerminalSequencesMatchModifierAndFunctionKeys(string codes, string expected) => Assert.Equal(expected, Encoding.UTF8.GetString(RemoteKeys.TerminalBytes(RemoteKeys.Parse(codes)!)!));
    [Fact]
    public void TerminalModesAndUnsupportedChordsAreExplicit()
    {
        Assert.Equal("\u001bOA", Encoding.ASCII.GetString(RemoteKeys.TerminalBytes([0xff52], applicationCursor: true)!));
        Assert.Equal(new byte[] { 8 }, RemoteKeys.TerminalBytes([0xff08], backspaceControlH: true));
        Assert.Null(RemoteKeys.TerminalBytes([0xffeb, 97]));
        Assert.Null(RemoteKeys.TerminalBytes([97, 98]));
        Assert.Null(RemoteKeys.Parse("97 97"));
        Assert.Null(RemoteKeys.Parse("1 2 3 4 5 6"));
    }
}
