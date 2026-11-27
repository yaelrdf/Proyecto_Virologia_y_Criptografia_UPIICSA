using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Discovery;

/// <summary>Anuncio UDP <c>CC-BEACON</c> (§6.1).</summary>
public sealed record Beacon
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = ProtocolConstants.BeaconType;

    [JsonPropertyName("protocolVersion")]
    public string ProtocolVersion { get; init; } = ProtocolConstants.ProtocolVersion;

    [JsonPropertyName("nodeId")]
    public required string NodeId { get; init; }

    [JsonPropertyName("teamNumber")]
    public required int TeamNumber { get; init; }

    [JsonPropertyName("ip")]
    public required string Ip { get; init; }

    [JsonPropertyName("httpPort")]
    public required int HttpPort { get; init; }

    [JsonPropertyName("httpsPort")]
    public int? HttpsPort { get; init; }

    [JsonPropertyName("status")]
    public required string Status { get; init; }

    [JsonPropertyName("algorithms")]
    public required IReadOnlyList<string> Algorithms { get; init; }

    [JsonPropertyName("certificateThumbprintSha256")]
    public required string CertificateThumbprintSha256 { get; init; }

    [JsonPropertyName("timestampUtc")]
    public required string TimestampUtc { get; init; }
}

/// <summary>Serialización y filtrado de anuncios (§6.1).</summary>
public static class BeaconCodec
{
    private static readonly JsonSerializerOptions Options = new() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>JSON UTF-8 sin compresión, ≤ 1024 bytes.</summary>
    public static byte[] Encode(Beacon beacon)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(beacon, Options);
        return bytes.Length <= ProtocolConstants.BeaconMaxBytes
            ? bytes
            : throw new InvalidOperationException("El anuncio supera 1024 bytes.");
    }

    /// <summary>
    /// Devuelve el anuncio si es válido y ajeno; nulo si debe ignorarse: propio, <c>type</c> o
    /// <c>protocolVersion</c> distintos, demasiado grande o mal formado.
    /// </summary>
    public static Beacon? Decode(ReadOnlySpan<byte> datagram, string ownNodeId)
    {
        if (datagram.Length is 0 or > ProtocolConstants.BeaconMaxBytes)
        {
            return null;
        }

        try
        {
            var beacon = JsonSerializer.Deserialize<Beacon>(datagram, Options);
            if (beacon is null
                || beacon.Type != ProtocolConstants.BeaconType
                || beacon.ProtocolVersion != ProtocolConstants.ProtocolVersion
                || !Identifiers.IsNodeId(beacon.NodeId)
                || beacon.NodeId == ownNodeId
                || beacon.NodeId != ProtocolConstants.NodeIdFor(beacon.TeamNumber)
                || beacon.HttpPort is <= 0 or > 65535
                || string.IsNullOrWhiteSpace(beacon.Ip))
            {
                return null;
            }

            return beacon;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static string Describe(byte[] encoded) => Encoding.UTF8.GetString(encoded);
}
