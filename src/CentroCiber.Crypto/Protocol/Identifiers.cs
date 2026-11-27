using System.Globalization;
using System.Text.RegularExpressions;

namespace CentroCiber.Crypto.Protocol;

/// <summary>Validadores de los identificadores de la sección 3 del estándar.</summary>
public static partial class Identifiers
{
    public const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'";

    [GeneratedRegex("^EQ[0-9]{2}$", RegexOptions.CultureInvariant)]
    private static partial Regex NodeIdRegex();

    [GeneratedRegex("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", RegexOptions.CultureInvariant)]
    private static partial Regex UuidV4Regex();

    [GeneratedRegex("^EQ[0-9]{2}-KEY-[0-9a-f-]{36}$", RegexOptions.CultureInvariant)]
    private static partial Regex KeyIdRegex();

    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", RegexOptions.CultureInvariant)]
    private static partial Regex TimestampRegex();

    [GeneratedRegex("^[0-9A-F]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex ThumbprintRegex();

    [GeneratedRegex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex ContentHashRegex();

    [GeneratedRegex("^(forward|inverse)$", RegexOptions.CultureInvariant)]
    private static partial Regex OperationRegex();

    public static bool IsNodeId(string? value) => value is not null && NodeIdRegex().IsMatch(value);

    public static bool IsTeamNumber(int value) => value is >= 1 and <= 99;

    public static bool IsAlgorithmId(int value) => value is >= 1 and <= 21;

    public static bool IsUuidV4(string? value) => value is not null && UuidV4Regex().IsMatch(value);

    public static bool IsKeyId(string? value) => value is not null && KeyIdRegex().IsMatch(value);

    public static bool IsTimestamp(string? value) =>
        value is not null && TimestampRegex().IsMatch(value) && TryParseTimestamp(value, out _);

    public static bool IsThumbprint(string? value) => value is not null && ThumbprintRegex().IsMatch(value);

    public static bool IsContentHash(string? value) => value is not null && ContentHashRegex().IsMatch(value);

    public static bool IsOperation(string? value) => value is not null && OperationRegex().IsMatch(value);

    /// <summary>Nuevo UUID v4 en minúsculas (packetId, requestId, jobId).</summary>
    public static string NewUuid() => Guid.NewGuid().ToString("D");

    public static string FormatTimestamp(DateTimeOffset value) =>
        value.UtcDateTime.ToString(TimestampFormat, CultureInfo.InvariantCulture);

    public static bool TryParseTimestamp(string value, out DateTimeOffset result)
    {
        if (DateTime.TryParseExact(value, TimestampFormat, CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var dt))
        {
            result = new DateTimeOffset(dt, TimeSpan.Zero);
            return true;
        }

        result = default;
        return false;
    }

    /// <summary>Trunca a segundos, como exige el formato <c>timestampUtc</c>.</summary>
    public static DateTimeOffset TruncateToSeconds(DateTimeOffset value) =>
        new(value.UtcTicks - (value.UtcTicks % TimeSpan.TicksPerSecond), TimeSpan.Zero);
}
