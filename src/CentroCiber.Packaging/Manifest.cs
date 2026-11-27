using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using CentroCiber.Crypto.Envelope;

namespace CentroCiber.Packaging;

/// <summary>Parte de un contenido <c>multipart</c> (§9.4).</summary>
public sealed record ManifestPart
{
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("sizeBytes")]
    public required long SizeBytes { get; init; }

    [JsonPropertyName("sha256")]
    public required string Sha256 { get; init; }
}

/// <summary>Referencia a una llave guardada por el dueño del algoritmo (§12).</summary>
public sealed record KeyRef
{
    [JsonPropertyName("keyId")]
    public required string KeyId { get; init; }

    [JsonPropertyName("ownerNode")]
    public required string OwnerNode { get; init; }
}

/// <summary>Veredicto de <c>inverse</c> para hash, MAC y firma (§9.5).</summary>
public sealed record Verification
{
    [JsonPropertyName("valid")]
    public required bool Valid { get; init; }

    [JsonPropertyName("detail")]
    public required string Detail { get; init; }
}

/// <summary><c>manifest.json</c> v2.0 (§9.5). Todos los campos se serializan, incluso los nulos.</summary>
public sealed record Manifest
{
    [JsonPropertyName("version")]
    public required string Version { get; init; }

    [JsonPropertyName("packetType")]
    public required string PacketType { get; init; }

    [JsonPropertyName("packetId")]
    public required string PacketId { get; init; }

    [JsonPropertyName("requestId")]
    public string? RequestId { get; init; }

    [JsonPropertyName("sourceNode")]
    public required string SourceNode { get; init; }

    [JsonPropertyName("sourceTeam")]
    public required int SourceTeam { get; init; }

    [JsonPropertyName("sourceIp")]
    public required string SourceIp { get; init; }

    [JsonPropertyName("producerNode")]
    public required string ProducerNode { get; init; }

    [JsonPropertyName("timestampUtc")]
    public required string TimestampUtc { get; init; }

    [JsonPropertyName("algorithmId")]
    public required int AlgorithmId { get; init; }

    [JsonPropertyName("algorithmCode")]
    public required string AlgorithmCode { get; init; }

    [JsonPropertyName("algorithmName")]
    public required string AlgorithmName { get; init; }

    [JsonPropertyName("operation")]
    public required string Operation { get; init; }

    [JsonPropertyName("operationName")]
    public required string OperationName { get; init; }

    [JsonPropertyName("payloadMode")]
    public required string PayloadMode { get; init; }

    [JsonPropertyName("originalFileName")]
    public required string OriginalFileName { get; init; }

    [JsonPropertyName("originalExtension")]
    public required string OriginalExtension { get; init; }

    [JsonPropertyName("originalSizeBytes")]
    public required long OriginalSizeBytes { get; init; }

    [JsonPropertyName("contentType")]
    public required string ContentType { get; init; }

    [JsonPropertyName("encryptedSha256")]
    public required string EncryptedSha256 { get; init; }

    [JsonPropertyName("encryptedSizeBytes")]
    public required long EncryptedSizeBytes { get; init; }

    [JsonPropertyName("parts")]
    public IReadOnlyList<ManifestPart>? Parts { get; init; }

    [JsonPropertyName("keyRef")]
    public KeyRef? KeyRef { get; init; }

    [JsonPropertyName("publicParameters")]
    public required IReadOnlyDictionary<string, string> PublicParameters { get; init; }

    [JsonPropertyName("publicParametersSha256")]
    public required string PublicParametersSha256 { get; init; }

    [JsonPropertyName("verification")]
    public Verification? Verification { get; init; }

    [JsonPropertyName("resultEnvelope")]
    public CcEnvelope? ResultEnvelope { get; init; }

    [JsonPropertyName("certificateThumbprintSha256")]
    public required string CertificateThumbprintSha256 { get; init; }

    [JsonPropertyName("signatureAlgorithm")]
    public required string SignatureAlgorithm { get; init; }

    [JsonPropertyName("manifestSignatureBase64")]
    public required string ManifestSignatureBase64 { get; init; }
}

/// <summary>Opciones JSON del protocolo (camelCase, UTF-8 sin escapar acentos, nulos incluidos).</summary>
public static class ProtocolJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip,
    };

    public static readonly JsonSerializerOptions Compact = new(Options) { WriteIndented = false };
}
