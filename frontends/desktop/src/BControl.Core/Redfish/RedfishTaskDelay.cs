using System.Globalization;

namespace BControl.Core.Redfish;

public static class RedfishTaskDelay
{
    public static long Due(string value, long monotonicNow, DateTimeOffset utcNow)
    {
        double seconds;
        if (value.Length == 0) seconds = 1;
        else if (value.All(c => c is >= '0' and <= '9') && ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var numeric)) seconds = Math.Max(1, numeric);
        else {
            var culture = (CultureInfo)CultureInfo.InvariantCulture.Clone();
            culture.DateTimeFormat.Calendar = new GregorianCalendar { TwoDigitYearMax = Math.Clamp(utcNow.Year + 50, 99, 9999) };
            if (!DateTimeOffset.TryParseExact(value, ["r", "dddd, dd-MMM-yy HH:mm:ss 'GMT'", "ddd MMM d HH:mm:ss yyyy"],
                culture, DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var date)) return long.MaxValue;
            seconds = Math.Max(1, (date - utcNow).TotalSeconds);
        }
        var delay = seconds * 1000;
        return delay >= long.MaxValue - monotonicNow ? long.MaxValue : monotonicNow + (long)Math.Ceiling(delay);
    }
}
