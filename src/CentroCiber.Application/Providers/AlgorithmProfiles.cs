using CentroCiber.Crypto.Algorithms;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Packaging.Contracts;

namespace CentroCiber.Application.Providers;

/// <summary>Perfiles publicados en <c>GET /api/algorithms</c> (§10.4) para los algoritmos propios.</summary>
public static class AlgorithmProfiles
{
    private static readonly string[] PayloadModes =
        [ProtocolConstants.PayloadText, ProtocolConstants.PayloadFile, ProtocolConstants.PayloadImage];

    public static AlgorithmProfile For(ILocalAlgorithm algorithm, IReadOnlySet<string> enabledVariants)
    {
        var info = AlgorithmCatalog.ByCode(algorithm.Code)!;
        var variants = algorithm.Variants.Where(enabledVariants.Contains).ToList();
        var operations = new Dictionary<string, ProfileOperation>
        {
            [ProtocolConstants.OperationForward] = new(info.ForwardName, [ProtocolConstants.PartPayload]),
            [ProtocolConstants.OperationInverse] = new(info.InverseName, [ProtocolConstants.PartPackage]),
        };

        return algorithm switch
        {
            HashShaAlgorithm => new AlgorithmProfile
            {
                AlgorithmId = info.Id,
                AlgorithmCode = info.Code,
                Variants = variants,
                Operations = operations,
                SecretParameters = [],
                Options =
                [
                    new ProfileOption { Name = HashShaAlgorithm.OptionHashAlgorithm, Type = "enum", Values = variants, Default = variants.FirstOrDefault() },
                ],
                PublicParameters = [HashShaAlgorithm.OptionHashAlgorithm, HashShaAlgorithm.ParamDigestHex],
                PayloadModes = PayloadModes,
                MaxPayloadBytes = ProtocolConstants.MaxBodyBytes,
            },
            HmacSha256Algorithm => new AlgorithmProfile
            {
                AlgorithmId = info.Id,
                AlgorithmCode = info.Code,
                Variants = variants,
                Operations = operations,
                SecretParameters =
                [
                    new ProfileSecret
                    {
                        Name = HmacSha256Algorithm.SecretKey,
                        Type = "base64",
                        MinBytes = HmacSha256Algorithm.MinKeyBytes,
                        RequiredFor = [ProtocolConstants.OperationForward, ProtocolConstants.OperationInverse],
                    },
                ],
                Options =
                [
                    new ProfileOption { Name = HmacSha256Algorithm.OptionMacAlgorithm, Type = "enum", Values = variants, Default = variants.FirstOrDefault() },
                ],
                PublicParameters = [HmacSha256Algorithm.OptionMacAlgorithm, HmacSha256Algorithm.ParamMacHex],
                PayloadModes = PayloadModes,
                MaxPayloadBytes = ProtocolConstants.MaxBodyBytes,
            },
            _ => Generic(info),
        };
    }

    /// <summary>Perfil mínimo deducido de la tabla 4.2, para algoritmos ajenos cuyo dueño no publicó perfil.</summary>
    public static AlgorithmProfile Generic(AlgorithmInfo info) => new()
    {
        AlgorithmId = info.Id,
        AlgorithmCode = info.Code,
        Variants = [],
        Operations = new Dictionary<string, ProfileOperation>
        {
            [ProtocolConstants.OperationForward] = new(info.ForwardName,
                info.Code == "LSBSTEGO" ? [ProtocolConstants.PartPayload, ProtocolConstants.PartCover] : [ProtocolConstants.PartPayload]),
            [ProtocolConstants.OperationInverse] = new(info.InverseName, [ProtocolConstants.PartPackage]),
        },
        SecretParameters = info.SecretParameters.Select(s => new ProfileSecret
        {
            Name = s,
            Type = "string",
            RequiredFor = info.KeyKind == KeyKind.OptionalSecret ? [] : [ProtocolConstants.OperationForward, ProtocolConstants.OperationInverse],
        }).ToList(),
        Options = [],
        PublicParameters = info.PublicParameters,
        PayloadModes = PayloadModes,
        MaxPayloadBytes = ProtocolConstants.MaxBodyBytes,
    };
}
