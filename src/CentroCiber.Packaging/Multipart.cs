using System.Globalization;
using System.Security.Cryptography;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Packaging;

/// <summary>Contenido <c>multipart</c> (§9.4): <c>datos.enc</c> es un zip interno con <c>part-01.bin</c>, …</summary>
public static class Multipart
{
    public static string PartName(int index) =>
        ProtocolConstants.MultipartPartPrefix + index.ToString("00", CultureInfo.InvariantCulture) + ProtocolConstants.MultipartPartSuffix;

    public static (byte[] InnerZip, IReadOnlyList<ManifestPart> Parts) Build(IReadOnlyList<byte[]> parts, DateTimeOffset timestamp)
    {
        if (parts.Count is 0 or > ProtocolConstants.MultipartMaxEntries)
        {
            throw new ArgumentOutOfRangeException(nameof(parts), "Entre 1 y 64 partes.");
        }

        var named = parts.Select((p, i) => (Name: PartName(i + 1), Data: p)).ToList();
        var inner = ZipSafety.Write(named.Select(p => (p.Name, p.Data, false)), timestamp);
        var manifestParts = named.Select(p => new ManifestPart
        {
            Name = p.Name,
            SizeBytes = p.Data.Length,
            Sha256 = Hex.Lower(SHA256.HashData(p.Data)),
        }).ToList();
        return (inner, manifestParts);
    }

    /// <summary>Lee y verifica las partes (§9.4 y §13.1 #8).</summary>
    public static IReadOnlyList<byte[]> ReadAndVerify(byte[] innerZip, IReadOnlyList<ManifestPart>? parts)
    {
        if (parts is null || parts.Count == 0)
        {
            throw new ProtocolException(ErrorCodes.Manifest, "payloadMode multipart requiere el arreglo parts.");
        }

        using var archive = ZipSafety.Open(innerZip);
        var entries = archive.Entries;
        if (entries.Count > ProtocolConstants.MultipartMaxEntries || entries.Count != parts.Count
            || entries.Any(e => !ZipSafety.IsFlatName(e.FullName))
            || entries.Select(e => e.FullName).Distinct(StringComparer.Ordinal).Count() != entries.Count)
        {
            throw new ProtocolException(ErrorCodes.ZipStructure, "El zip interno de datos.enc no cumple §9.4.");
        }

        ZipSafety.CheckBomb(entries, ProtocolConstants.MaxUncompressedBytes);
        var result = new List<byte[]>();
        foreach (var part in parts)
        {
            var entry = archive.GetEntry(part.Name)
                ?? throw new ProtocolException(ErrorCodes.Hash, $"Falta la parte {part.Name}.");
            var data = ZipSafety.ReadAll(entry);
            if (data.Length != part.SizeBytes
                || !CryptographicOperations.FixedTimeEquals(Convert.FromHexString(part.Sha256), SHA256.HashData(data)))
            {
                throw new ProtocolException(ErrorCodes.Hash, $"El SHA-256 de {part.Name} no coincide.");
            }

            result.Add(data);
        }

        return result;
    }
}
