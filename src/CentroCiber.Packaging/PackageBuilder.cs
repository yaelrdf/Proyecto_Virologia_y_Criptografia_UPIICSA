using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CentroCiber.Crypto.Envelope;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Crypto.Signing;

namespace CentroCiber.Packaging;

/// <summary>Contenido lógico de un paquete antes de firmarlo.</summary>
public sealed record PackageContent
{
    public required string PacketType { get; init; }

    public required string AlgorithmCode { get; init; }

    public required string AlgorithmName { get; init; }

    public required string Operation { get; init; }

    public required string PayloadMode { get; init; }

    public required string OriginalFileName { get; init; }

    public required long OriginalSizeBytes { get; init; }

    public string? ContentType { get; init; }

    /// <summary>Bytes de <c>datos.enc</c> (package) o <c>resultado.enc</c> (result).</summary>
    public required byte[] Data { get; init; }

    public IReadOnlyList<ManifestPart>? Parts { get; init; }

    public KeyRef? KeyRef { get; init; }

    public IReadOnlyDictionary<string, string> PublicParameters { get; init; } = new Dictionary<string, string>();

    public Verification? Verification { get; init; }

    public CcEnvelope? ResultEnvelope { get; init; }

    public string? RequestId { get; init; }

    /// <summary>Nulo = el firmante (sourceNode).</summary>
    public string? ProducerNode { get; init; }

    /// <summary>Nulo = generar uno nuevo. Para <c>result</c> se fija antes porque es el AAD del sobre.</summary>
    public string? PacketId { get; init; }
}

/// <summary>Paquete firmado listo para enviar.</summary>
public sealed record BuiltPackage(byte[] Zip, string FileName, Manifest Manifest);

/// <summary>Constructor de paquetes <c>package</c> y <c>result</c> v2.0 (§9).</summary>
public static class PackageBuilder
{
    public static BuiltPackage Build(PackageContent content, NodeIdentity signer, string sourceIp, TimeProvider clock)
    {
        var info = AlgorithmCatalog.ByCode(content.AlgorithmCode)
            ?? throw new ProtocolException(ErrorCodes.Algorithm, $"Algoritmo desconocido: {content.AlgorithmCode}.");
        var timestamp = Identifiers.TruncateToSeconds(clock.GetUtcNow());
        var teamNumber = int.Parse(signer.NodeId.AsSpan(2), System.Globalization.CultureInfo.InvariantCulture);
        var isResult = content.PacketType == ProtocolConstants.PacketTypeResult;

        var unsigned = new Manifest
        {
            Version = ProtocolConstants.ProtocolVersion,
            PacketType = content.PacketType,
            PacketId = content.PacketId ?? Identifiers.NewUuid(),
            RequestId = content.RequestId,
            SourceNode = signer.NodeId,
            SourceTeam = teamNumber,
            SourceIp = sourceIp,
            ProducerNode = content.ProducerNode ?? signer.NodeId,
            TimestampUtc = Identifiers.FormatTimestamp(timestamp),
            AlgorithmId = info.Id,
            AlgorithmCode = info.Code,
            AlgorithmName = content.AlgorithmName,
            Operation = content.Operation,
            OperationName = info.OperationName(content.Operation),
            PayloadMode = content.PayloadMode,
            OriginalFileName = content.OriginalFileName,
            OriginalExtension = Path.GetExtension(content.OriginalFileName),
            OriginalSizeBytes = content.OriginalSizeBytes,
            ContentType = content.ContentType ?? ContentTypes.ForFile(content.OriginalFileName, content.PayloadMode),
            EncryptedSha256 = Hex.Lower(SHA256.HashData(content.Data)),
            EncryptedSizeBytes = content.Data.Length,
            Parts = content.Parts,
            KeyRef = content.KeyRef,
            PublicParameters = content.PublicParameters,
            PublicParametersSha256 = CanonicalParameters.Hash(content.PublicParameters),
            Verification = isResult ? content.Verification : null,
            ResultEnvelope = isResult ? content.ResultEnvelope : null,
            CertificateThumbprintSha256 = signer.Thumbprint,
            SignatureAlgorithm = ProtocolConstants.SignatureAlgorithm,
            ManifestSignatureBase64 = string.Empty,
        };

        return Sign(unsigned, content.Data, signer, timestamp);
    }

    /// <summary>Firma la cadena 8.4 y arma el zip con los 3 archivos de §9.3.</summary>
    public static BuiltPackage Sign(Manifest unsigned, byte[] data, NodeIdentity signer, DateTimeOffset timestamp)
    {
        var signature = RsaPss.SignBase64(signer.PrivateKey, SignatureChain.Bytes(unsigned));
        var manifest = unsigned with { ManifestSignatureBase64 = signature };
        var manifestJson = JsonSerializer.SerializeToUtf8Bytes(manifest, ProtocolJson.Options);
        var dataEntry = manifest.PacketType == ProtocolConstants.PacketTypeResult
            ? ProtocolConstants.EntryResult
            : ProtocolConstants.EntryData;
        var zip = ZipSafety.Write(
        [
            (dataEntry, data, false),
            (ProtocolConstants.EntryCertificate, Encoding.ASCII.GetBytes(signer.CertificatePem), true),
            (ProtocolConstants.EntryManifest, manifestJson, true),
        ], timestamp);
        return new BuiltPackage(zip, PackageNaming.FileName(manifest), manifest);
    }
}
