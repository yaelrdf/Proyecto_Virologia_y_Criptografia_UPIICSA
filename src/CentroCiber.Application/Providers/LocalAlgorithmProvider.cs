using System.Security.Cryptography;
using CentroCiber.Application.Services;
using CentroCiber.Crypto.Algorithms;
using CentroCiber.Crypto.Envelope;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Packaging;

namespace CentroCiber.Application.Providers;

/// <summary>
/// Proveedor local (§11.5): ejecuta los algoritmos propios y produce paquetes idénticos en formato
/// a los de una llamada remota. Las variantes deshabilitadas en Ajustes se rechazan con <c>E-PARAMS</c>.
/// </summary>
public sealed class LocalAlgorithmProvider(
    NodeContext node,
    IEnumerable<ILocalAlgorithm> algorithms,
    PackageValidator validator,
    SettingsService settings) : IAlgorithmProvider
{
    private readonly Dictionary<string, ILocalAlgorithm> byCode = algorithms
        .Where(a => AlgorithmCatalog.ByCode(a.Code)?.OwnerTeam == node.TeamNumber)
        .ToDictionary(a => a.Code, StringComparer.Ordinal);

    public IReadOnlyCollection<ILocalAlgorithm> Algorithms => byCode.Values;

    public bool CanHandle(string algorithmCode) => byCode.ContainsKey(algorithmCode);

    public async Task<OperationResult> ForwardAsync(ForwardRequest request, CancellationToken ct)
    {
        var algorithm = Get(request.AlgorithmCode);
        if (request.Payload.LongLength > ProtocolConstants.MaxBodyBytes)
        {
            throw new ProtocolException(ErrorCodes.Size, "El contenido supera 50 MB.");
        }

        if (request.PayloadMode == ProtocolConstants.PayloadMultipart)
        {
            throw new ProtocolException(ErrorCodes.Params, $"{algorithm.Code} no acepta payloadMode multipart.");
        }

        var output = algorithm.Forward(new ForwardInput(request.Payload, request.Options, request.Secrets));
        await EnsureVariantEnabledAsync(output.AlgorithmName, ct);
        var built = PackageBuilder.Build(new PackageContent
        {
            PacketType = ProtocolConstants.PacketTypePackage,
            AlgorithmCode = algorithm.Code,
            AlgorithmName = output.AlgorithmName,
            Operation = ProtocolConstants.OperationForward,
            PayloadMode = request.PayloadMode,
            OriginalFileName = request.OriginalFileName,
            OriginalSizeBytes = request.Payload.LongLength,
            ContentType = request.ContentType,
            Data = output.Data,
            PublicParameters = output.PublicParameters,
            RequestId = request.RequestId,
        }, node.Identity, node.SourceIp, node.Clock);
        return new OperationResult { Zip = built.Zip, FileName = built.FileName, Manifest = built.Manifest, ProviderNode = node.NodeId };
    }

    public async Task<OperationResult> InverseAsync(InverseRequest request, CancellationToken ct)
    {
        var package = await validator.ValidateAsync(request.PackageZip, PackageValidationOptions.ForInverse, ct);
        return await InverseValidatedAsync(package, request, ct);
    }

    /// <summary><c>inverse</c> sobre un paquete ya validado (lo usa el manejador de <c>/api/crypto/inverse</c>).</summary>
    public async Task<OperationResult> InverseValidatedAsync(ValidatedPackage package, InverseRequest request, CancellationToken ct)
    {
        var m = package.Manifest;
        if (!string.Equals(m.AlgorithmCode, request.AlgorithmCode, StringComparison.Ordinal))
        {
            throw new ProtocolException(ErrorCodes.Request, "El algoritmo del paquete no coincide con el de la petición.");
        }

        var algorithm = Get(m.AlgorithmCode);
        var output = algorithm.Inverse(new InverseInput(package.Data, m.PublicParameters, request.Options, request.Secrets));
        await EnsureVariantEnabledAsync(output.AlgorithmName, ct);

        var me = node.Identity;
        var recipientCert = request.RecipientCertificate ?? me.Certificate;
        var recipientNode = request.RecipientNode ?? me.NodeId;
        var packetId = Identifiers.NewUuid();
        var sealedResult = EnvelopeCrypto.Seal(output.Original, recipientCert, recipientNode, packetId, includeCiphertext: false);
        var built = PackageBuilder.Build(new PackageContent
        {
            PacketType = ProtocolConstants.PacketTypeResult,
            PacketId = packetId,
            RequestId = request.RequestId,
            AlgorithmCode = m.AlgorithmCode,
            AlgorithmName = output.AlgorithmName,
            Operation = ProtocolConstants.OperationInverse,
            PayloadMode = m.PayloadMode,
            OriginalFileName = m.OriginalFileName,
            OriginalSizeBytes = output.Original.LongLength,
            ContentType = m.ContentType,
            Data = sealedResult.Ciphertext,
            KeyRef = m.KeyRef,
            Verification = output.Valid is { } valid ? new Verification { Valid = valid, Detail = output.Detail ?? string.Empty } : null,
            ResultEnvelope = sealedResult.Envelope,
        }, me, node.SourceIp, node.Clock);

        var forSelf = string.Equals(recipientNode, me.NodeId, StringComparison.Ordinal);
        var original = forSelf ? output.Original : null;
        if (!forSelf)
        {
            CryptographicOperations.ZeroMemory(output.Original);
        }

        return new OperationResult
        {
            Zip = built.Zip,
            FileName = built.FileName,
            Manifest = built.Manifest,
            Original = original,
            ProviderNode = me.NodeId,
        };
    }

    private ILocalAlgorithm Get(string code) =>
        byCode.TryGetValue(code, out var a)
            ? a
            : throw new ProtocolException(ErrorCodes.AlgorithmNotProvided, $"Este nodo no provee {code}.");

    private async Task EnsureVariantEnabledAsync(string variant, CancellationToken ct)
    {
        var enabled = await settings.EnabledVariantsAsync(ct);
        if (!enabled.Contains(variant))
        {
            throw new ProtocolException(ErrorCodes.Params, $"La variante {variant} está deshabilitada en este nodo.");
        }
    }
}
