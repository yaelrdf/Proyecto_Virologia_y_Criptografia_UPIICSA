using System.Security.Cryptography;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Crypto.Algorithms;

/// <summary>
/// <c>HASHSHA</c> (#15): <c>forward</c> calcula SHA-256 o SHA-512 y deja el original en <c>datos.enc</c>;
/// <c>inverse</c> recalcula y compara en tiempo constante (§4.2, §4.3).
/// </summary>
public sealed class HashShaAlgorithm : ILocalAlgorithm
{
    public const string OptionHashAlgorithm = "hashAlgorithm";
    public const string ParamDigestHex = "digestHex";
    public const string Sha256 = "SHA-256";
    public const string Sha512 = "SHA-512";

    public string Code => AlgorithmCatalog.HashSha;

    public IReadOnlyList<string> Variants { get; } = [Sha256, Sha512];

    public static byte[] Compute(string variant, ReadOnlySpan<byte> data) => variant switch
    {
        Sha256 => SHA256.HashData(data),
        Sha512 => SHA512.HashData(data),
        _ => throw new ProtocolException(ErrorCodes.Params,
            $"hashAlgorithm debe ser {Sha256} o {Sha512} (SHA3-256 no se ofrece en este nodo)."),
    };

    public ForwardOutput Forward(ForwardInput input)
    {
        ParameterRules.RejectSecrets(input.Secrets, Code);
        ParameterRules.AllowOnly(input.Options, OptionHashAlgorithm);
        var variant = input.Options.GetValueOrDefault(OptionHashAlgorithm, Sha256);
        var digest = Compute(variant, input.Data);
        return new ForwardOutput(input.Data, new Dictionary<string, string>
        {
            [OptionHashAlgorithm] = variant,
            [ParamDigestHex] = Hex.Lower(digest),
        }, variant);
    }

    public InverseOutput Inverse(InverseInput input)
    {
        ParameterRules.RejectSecrets(input.Secrets, Code);
        ParameterRules.AllowOnly(input.Options, OptionHashAlgorithm);
        var variant = ParameterRules.Require(input.PublicParameters, OptionHashAlgorithm);
        var expectedHex = ParameterRules.Require(input.PublicParameters, ParamDigestHex);
        var actual = Compute(variant, input.Data);
        var valid = Hex.TryDecode(expectedHex, out var expected) && CryptographicOperations.FixedTimeEquals(actual, expected);
        return new InverseOutput(input.Data, valid, valid ? "Hash coincide" : "Hash no coincide", variant);
    }
}
