using System.Text.Json.Serialization;
using CentroCiber.Crypto.Envelope;

namespace CentroCiber.Packaging.Contracts;

/// <summary>Algoritmo anunciado en <c>GET /api/status</c> (§10.3).</summary>
public sealed record StatusAlgorithm(
    [property: JsonPropertyName("algorithmId")] int AlgorithmId,
    [property: JsonPropertyName("algorithmCode")] string AlgorithmCode);

/// <summary><c>GET /api/status</c> (§10.3).</summary>
public sealed record StatusResponse
{
    [JsonPropertyName("nodeId")]
    public required string NodeId { get; init; }

    [JsonPropertyName("teamNumber")]
    public required int TeamNumber { get; init; }

    [JsonPropertyName("protocolVersion")]
    public required string ProtocolVersion { get; init; }

    [JsonPropertyName("status")]
    public required string Status { get; init; }

    [JsonPropertyName("acceptingPackages")]
    public required bool AcceptingPackages { get; init; }

    [JsonPropertyName("httpPort")]
    public required int HttpPort { get; init; }

    [JsonPropertyName("httpsPort")]
    public int? HttpsPort { get; init; }

    [JsonPropertyName("algorithms")]
    public required IReadOnlyList<StatusAlgorithm> Algorithms { get; init; }

    [JsonPropertyName("certificateThumbprintSha256")]
    public required string CertificateThumbprintSha256 { get; init; }

    [JsonPropertyName("serverTimeUtc")]
    public required string ServerTimeUtc { get; init; }

    /// <summary>Extensión compatible (campos desconocidos se ignoran, §9.5): versiones de protocolo que habla el nodo.</summary>
    [JsonPropertyName("supportedProtocolVersions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? SupportedProtocolVersions { get; init; }

    /// <summary>Extensión: versión del software del nodo.</summary>
    [JsonPropertyName("nodeVersion")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NodeVersion { get; init; }
}

/// <summary>Operación descrita en el perfil (§10.4).</summary>
public sealed record ProfileOperation(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("inputs")] IReadOnlyList<string> Inputs);

/// <summary>Parámetro secreto del perfil (§10.4).</summary>
public sealed record ProfileSecret
{
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("type")]
    public required string Type { get; init; }

    [JsonPropertyName("minBytes")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? MinBytes { get; init; }

    [JsonPropertyName("requiredFor")]
    public required IReadOnlyList<string> RequiredFor { get; init; }
}

/// <summary>Opción pública del perfil (§10.4).</summary>
public sealed record ProfileOption
{
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("type")]
    public required string Type { get; init; }

    [JsonPropertyName("values")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? Values { get; init; }

    [JsonPropertyName("default")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Default { get; init; }
}

/// <summary>Perfil de un algoritmo (§10.4).</summary>
public sealed record AlgorithmProfile
{
    [JsonPropertyName("algorithmId")]
    public required int AlgorithmId { get; init; }

    [JsonPropertyName("algorithmCode")]
    public required string AlgorithmCode { get; init; }

    [JsonPropertyName("variants")]
    public required IReadOnlyList<string> Variants { get; init; }

    [JsonPropertyName("operations")]
    public required IReadOnlyDictionary<string, ProfileOperation> Operations { get; init; }

    [JsonPropertyName("secretParameters")]
    public required IReadOnlyList<ProfileSecret> SecretParameters { get; init; }

    [JsonPropertyName("options")]
    public required IReadOnlyList<ProfileOption> Options { get; init; }

    [JsonPropertyName("publicParameters")]
    public required IReadOnlyList<string> PublicParameters { get; init; }

    [JsonPropertyName("payloadModes")]
    public required IReadOnlyList<string> PayloadModes { get; init; }

    [JsonPropertyName("maxPayloadBytes")]
    public required long MaxPayloadBytes { get; init; }

    /// <summary>Extensión usada por otros nodos (p. ej. EQ06): notas para el usuario sobre el algoritmo.</summary>
    [JsonPropertyName("notes")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Notes { get; init; }
}

/// <summary><c>GET /api/algorithms</c> (§10.4).</summary>
public sealed record AlgorithmsResponse(
    [property: JsonPropertyName("nodeId")] string NodeId,
    [property: JsonPropertyName("algorithms")] IReadOnlyList<AlgorithmProfile> Algorithms);

/// <summary>Respuesta <c>202</c> de <c>POST /api/requests/receive</c> (§10.5).</summary>
public sealed record ReceiveResponse(
    [property: JsonPropertyName("packetId")] string PacketId,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("receivedAtUtc")] string ReceivedAtUtc);

/// <summary>Objeto <c>request</c> de <c>/api/crypto/*</c> (§10.6).</summary>
public sealed record CryptoRequest
{
    [JsonPropertyName("version")]
    public required string Version { get; init; }

    [JsonPropertyName("requestId")]
    public required string RequestId { get; init; }

    [JsonPropertyName("requesterNode")]
    public required string RequesterNode { get; init; }

    [JsonPropertyName("targetNode")]
    public required string TargetNode { get; init; }

    [JsonPropertyName("timestampUtc")]
    public required string TimestampUtc { get; init; }

    [JsonPropertyName("algorithmCode")]
    public required string AlgorithmCode { get; init; }

    [JsonPropertyName("operation")]
    public required string Operation { get; init; }

    [JsonPropertyName("payloadMode")]
    public required string PayloadMode { get; init; }

    [JsonPropertyName("originalFileName")]
    public required string OriginalFileName { get; init; }

    [JsonPropertyName("options")]
    public IReadOnlyDictionary<string, string>? Options { get; init; }

    [JsonPropertyName("keyId")]
    public string? KeyId { get; init; }

    [JsonPropertyName("secrets")]
    public CcEnvelope? Secrets { get; init; }
}

/// <summary>Respuesta <c>202</c> con trabajo asíncrono (§10.6).</summary>
public sealed record JobAccepted(
    [property: JsonPropertyName("jobId")] string JobId,
    [property: JsonPropertyName("statusUrl")] string StatusUrl,
    [property: JsonPropertyName("retryAfterSeconds")] int RetryAfterSeconds);

/// <summary>Error de un trabajo fallido.</summary>
public sealed record JobError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("detail")] string Detail);

/// <summary><c>GET /api/jobs/{jobId}</c> (§10.7).</summary>
public sealed record JobStatusResponse
{
    [JsonPropertyName("jobId")]
    public required string JobId { get; init; }

    [JsonPropertyName("state")]
    public required string State { get; init; }

    [JsonPropertyName("progressPercent")]
    public required int ProgressPercent { get; init; }

    [JsonPropertyName("resultUrl")]
    public string? ResultUrl { get; init; }

    [JsonPropertyName("error")]
    public JobError? Error { get; init; }
}

/// <summary>Cuerpo <c>application/problem+json</c> (§14).</summary>
public sealed record ProblemDocument
{
    [JsonPropertyName("type")]
    public required string Type { get; init; }

    [JsonPropertyName("title")]
    public required string Title { get; init; }

    [JsonPropertyName("status")]
    public required int Status { get; init; }

    [JsonPropertyName("code")]
    public required string Code { get; init; }

    [JsonPropertyName("detail")]
    public required string Detail { get; init; }

    [JsonPropertyName("nodeId")]
    public required string NodeId { get; init; }

    [JsonPropertyName("requestId")]
    public string? RequestId { get; init; }

    [JsonPropertyName("timestampUtc")]
    public required string TimestampUtc { get; init; }
}
