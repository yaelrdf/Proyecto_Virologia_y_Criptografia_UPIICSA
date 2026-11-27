using System.Security.Cryptography;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Crypto.Algorithms;

/// <summary>
/// <c>HMACSHA256</c> (#16): <c>forward</c> calcula HMAC-SHA256 con la clave del solicitante (≥ 32 bytes);
/// <c>inverse</c> recalcula con la clave recibida y compara en tiempo constante. La clave nunca se guarda.
/// </summary>
public sealed class HmacSha256Algorithm : ILocalAlgorithm
{
    public const string SecretKey = "key";
    public const string OptionMacAlgorithm = "macAlgorithm";
    public const string ParamMacHex = "macHex";
    public const string HmacSha256 = "HMAC-SHA256";
    public const int MinKeyBytes = 32;

    public string Code => AlgorithmCatalog.HmacSha256;

    public IReadOnlyList<string> Variants { get; } = [HmacSha256];

    /// <summary>Primitiva HMAC-SHA256 sin restricción de longitud de clave (vectores RFC 4231).</summary>
    public static byte[] Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data) => HMACSHA256.HashData(key, data);

    public ForwardOutput Forward(ForwardInput input)
    {
        ParameterRules.AllowOnly(input.Options, OptionMacAlgorithm);
        var variant = Variant(input.Options.GetValueOrDefault(OptionMacAlgorithm, HmacSha256));
        var key = ReadKey(input.Secrets);
        try
        {
            var mac = Compute(key, input.Data);
            return new ForwardOutput(input.Data, new Dictionary<string, string>
            {
                [OptionMacAlgorithm] = variant,
                [ParamMacHex] = Hex.Lower(mac),
            }, variant);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public InverseOutput Inverse(InverseInput input)
    {
        ParameterRules.AllowOnly(input.Options, OptionMacAlgorithm);
        var variant = Variant(ParameterRules.Require(input.PublicParameters, OptionMacAlgorithm));
        var expectedHex = ParameterRules.Require(input.PublicParameters, ParamMacHex);
        var key = ReadKey(input.Secrets);
        try
        {
            var actual = Compute(key, input.Data);
            var valid = Hex.TryDecode(expectedHex, out var expected) && CryptographicOperations.FixedTimeEquals(actual, expected);
            return new InverseOutput(input.Data, valid, valid ? "HMAC coincide" : "HMAC no coincide", variant);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static string Variant(string value) => value == HmacSha256
        ? value
        : throw new ProtocolException(ErrorCodes.Params, $"macAlgorithm debe ser {HmacSha256} (HMAC-SHA512 no se ofrece en este nodo).");

    private static byte[] ReadKey(IReadOnlyDictionary<string, string> secrets)
    {
        ParameterRules.AllowOnly(secrets, SecretKey);
        if (!secrets.TryGetValue(SecretKey, out var b64) || string.IsNullOrEmpty(b64))
        {
            throw new ProtocolException(ErrorCodes.Params, "Falta el secreto 'key' (Base64, ≥ 32 bytes).");
        }

        byte[] key;
        try
        {
            key = Convert.FromBase64String(b64);
        }
        catch (FormatException ex)
        {
            throw new ProtocolException(ErrorCodes.Params, "El secreto 'key' no es Base64 válido.", ex);
        }

        if (key.Length < MinKeyBytes)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new ProtocolException(ErrorCodes.Params, $"La clave HMAC debe medir al menos {MinKeyBytes} bytes.");
        }

        return key;
    }
}
