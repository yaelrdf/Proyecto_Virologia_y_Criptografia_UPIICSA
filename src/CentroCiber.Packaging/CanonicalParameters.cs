using System.Security.Cryptography;
using System.Text;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Packaging;

/// <summary>Hash canónico de <c>publicParameters</c> (§8.5).</summary>
public static class CanonicalParameters
{
    /// <summary>SHA-256 de la cadena vacía (§8.5 paso 6).</summary>
    public const string EmptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// <summary>
    /// Texto canónico: llaves ordenadas por bytes UTF-8 (ordinal ascendente), una línea
    /// <c>llave=valor</c> por par, unidas con LF y sin salto final.
    /// </summary>
    public static string CanonicalText(IReadOnlyDictionary<string, string> parameters)
    {
        var keys = parameters.Keys.ToList();
        keys.Sort(Utf8OrdinalComparer.Instance);
        return string.Join('\n', keys.Select(k => k + "=" + parameters[k]));
    }

    public static string Hash(IReadOnlyDictionary<string, string> parameters) =>
        Hex.Lower(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalText(parameters))));

    /// <summary>Comparación ordinal sobre los bytes UTF-8 (distinta de UTF-16 fuera del BMP).</summary>
    public sealed class Utf8OrdinalComparer : IComparer<string>
    {
        public static readonly Utf8OrdinalComparer Instance = new();

        public int Compare(string? x, string? y)
        {
            if (ReferenceEquals(x, y))
            {
                return 0;
            }

            if (x is null)
            {
                return -1;
            }

            if (y is null)
            {
                return 1;
            }

            return Encoding.UTF8.GetBytes(x).AsSpan().SequenceCompareTo(Encoding.UTF8.GetBytes(y));
        }
    }
}
