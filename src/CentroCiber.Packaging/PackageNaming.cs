using System.Globalization;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Packaging;

/// <summary>Nomenclatura de los zips (§9.2). Es informativa: el receptor valida contra el manifiesto.</summary>
public static class PackageNaming
{
    public static string FileName(Manifest m)
    {
        if (!Identifiers.TryParseTimestamp(m.TimestampUtc, out var ts))
        {
            throw new ArgumentException("timestampUtc inválido.", nameof(m));
        }

        var stamp = ts.UtcDateTime.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var sha8 = m.EncryptedSha256[..8].ToUpperInvariant();
        var baseName = $"{m.SourceNode}_{m.AlgorithmCode}_{stamp}_{sha8}{ProtocolConstants.ZipExtension}";
        return m.PacketType == ProtocolConstants.PacketTypeResult ? ProtocolConstants.ResultFilePrefix + baseName : baseName;
    }
}
