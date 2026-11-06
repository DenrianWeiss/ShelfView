using System.Globalization;
using System.Text;

namespace BControl.Core.Input;
public sealed record KeyCombination(string Name, uint[] Keys)
{
    public string Label => string.IsNullOrWhiteSpace(Name) ? string.Join("+", Keys.Select(RemoteKeys.Label)) : Name;
}

public static class RemoteKeys
{
    private static readonly HashSet<uint> Modifiers = [0xffe1, 0xffe2, 0xffe3, 0xffe4, 0xffe9, 0xffea, 0xffeb, 0xffec];
    private static readonly Dictionary<uint, string> Names = new()
    {
        [0xffe3] = "Ctrl",
        [0xffe4] = "Ctrl (R)",
        [0xffe1] = "Shift",
        [0xffe2] = "Shift (R)",
        [0xffe9] = "Alt",
        [0xffea] = "Alt (R)",
        [0xffeb] = "Super",
        [0xffec] = "Super (R)",
        [0xff1b] = "Esc",
        [0xff09] = "Tab",
        [0xff0d] = "Enter",
        [0xff08] = "Backspace",
        [0xffff] = "Delete",
        [0xff63] = "Insert",
        [0xff50] = "Home",
        [0xff57] = "End",
        [0xff55] = "Page Up",
        [0xff56] = "Page Down",
        [0xff51] = "←",
        [0xff52] = "↑",
        [0xff53] = "→",
        [0xff54] = "↓",
        [32] = "Space"
    };
    public static IReadOnlyList<KeyCombination> Special => new uint[]
    {
        0xff1b,
        0xff09,
        0xff0d,
        0xff08,
        0xff63,
        0xffff,
        0xff50,
        0xff57,
        0xff55,
        0xff56,
        0xff51,
        0xff52,
        0xff53,
        0xff54
    }.Select(key => new KeyCombination("", [key])).ToArray();
    public static IReadOnlyList<KeyCombination> Functions => Enumerable.Range(0, 12).Select(i => new KeyCombination("", [(uint)(0xffbe + i)])).ToArray();
    public static IReadOnlyList<KeyCombination> Presets => new[]
    {
        new KeyCombination("", [0xffe3, 0xffe9, 0xffff]),
        new KeyCombination("", [0xffe3, 0xffe9, 0xff08]),
        new KeyCombination("", [0xffe9, 0xff09]),
        new KeyCombination("", [0xffe3, 0xff1b])
    };

    public static uint[]? Order(IEnumerable<uint> values)
    {
        var keys = values.ToArray();
        if (keys.Length is < 1 or > 5 || keys.Distinct().Count() != keys.Length || keys.Any(key => key is 0 or > 0x1fffffff))
            return null;
        return keys.Where(Modifiers.Contains).Concat(keys.Where(key => !Modifiers.Contains(key))).ToArray();
    }

    public static uint[]? Parse(string text)
    {
        var values = new List<uint>();
        foreach (var token in text.Split([' ', ',', '+', '\t', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var hex = token.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
            if (!uint.TryParse(hex ? token[2..] : token, hex ? NumberStyles.HexNumber : NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                return null;
            values.Add(value);
        }

        return Order(values);
    }

    public static string Label(uint key) => Names.TryGetValue(key, out var value) ? value : key is >= 0xffbe and <= 0xffc9 ? $"F{key - 0xffbe + 1}" : key is >= 0x21 and <= 0x7e ? ((char)key).ToString().ToUpperInvariant() : $"0x{key:X}";
    public static byte[]? TerminalBytes(IEnumerable<uint> values, bool applicationCursor = false, bool backspaceControlH = false)
    {
        var keys = Order(values);
        if (keys == null || keys.Any(key => key is 0xffeb or 0xffec))
            return null;
        var main = keys.Where(key => !Modifiers.Contains(key)).ToArray();
        if (main.Length != 1)
            return null;
        var key = main[0];
        var ctrl = keys.Any(k => k is 0xffe3 or 0xffe4);
        var shift = keys.Any(k => k is 0xffe1 or 0xffe2);
        var alt = keys.Any(k => k is 0xffe9 or 0xffea);
        var parameter = 1 + (shift ? 1 : 0) + (alt ? 2 : 0) + (ctrl ? 4 : 0);
        var final = key switch
        {
            0xff51 => "D",
            0xff52 => "A",
            0xff53 => "C",
            0xff54 => "B",
            0xff50 => "H",
            0xff57 => "F",
            0xffbe => "P",
            0xffbf => "Q",
            0xffc0 => "R",
            0xffc1 => "S",
            _ => null
        };
        if (final != null)
            return Encoding.ASCII.GetBytes((parameter > 1 ? $"\u001b[1;{parameter}" : applicationCursor || key >= 0xffbe ? "\u001bO" : "\u001b[") + final);
        var numbered = key switch
        {
            0xff63 => 2,
            0xffff => 3,
            0xff55 => 5,
            0xff56 => 6,
            0xffc2 => 15,
            0xffc3 => 17,
            0xffc4 => 18,
            0xffc5 => 19,
            0xffc6 => 20,
            0xffc7 => 21,
            0xffc8 => 23,
            0xffc9 => 24,
            _ => 0
        };
        if (numbered > 0)
            return Encoding.ASCII.GetBytes($"\u001b[{numbered}" + (parameter > 1 ? $";{parameter}" : "") + "~");
        if (key == 0xff09 && shift && !ctrl)
            return Encoding.ASCII.GetBytes(alt ? "\u001b\u001b[Z" : "\u001b[Z");
        byte[] result;
        var simple = key switch
        {
            0xff1b => 27,
            0xff09 => 9,
            0xff0d => 13,
            0xff08 => backspaceControlH ? 8 : 127,
            _ => -1
        };
        if (simple >= 0)
        {
            if (ctrl || shift)
                return null;
            result = [(byte)simple];
        }
        else if (ctrl)
        {
            var upper = key is >= 0x61 and <= 0x7a ? key - 32 : key;
            if (upper is >= 0x40 and <= 0x5f)
                result = [(byte)(upper & 31)];
            else if (key == 32)
                result = [0];
            else if (key == 63)
                result = [127];
            else
                return null;
        }
        else
        {
            if (shift)
            {
                if (key is >= 0x61 and <= 0x7a)
                    key -= 32;
                else
                    return null;
            }

            var scalar = (key & 0xff000000) == 0x01000000 ? key & 0xffffff : key;
            if (scalar < 32 || !Rune.IsValid((int)scalar) || ((key & 0xff000000) != 0x01000000 && scalar > 255))
                return null;
            result = Encoding.UTF8.GetBytes(new Rune((int)scalar).ToString());
        }

        return alt ? new byte[]
        {
            27
        }.Concat(result).ToArray() : result;
    }
}
