using System.Text.Json.Serialization;

namespace CentroCiber.Crypto.Envelope;

/// <summary>Sobre híbrido <c>CC-ENV-1</c> (§8.3). En <c>resultEnvelope</c> va sin <c>ciphertextBase64</c>.</summary>
public sealed record CcEnvelope
{
    [JsonPropertyName("envelope")]
    public required string Envelope { get; init; }

    [JsonPropertyName("recipientNode")]
    public required string RecipientNode { get; init; }

    [JsonPropertyName("recipientThumbprintSha256")]
    public required string RecipientThumbprintSha256 { get; init; }

    [JsonPropertyName("wrappedKeyBase64")]
    public required string WrappedKeyBase64 { get; init; }

    [JsonPropertyName("nonceBase64")]
    public required string NonceBase64 { get; init; }

    [JsonPropertyName("tagBase64")]
    public required string TagBase64 { get; init; }

    [JsonPropertyName("ciphertextBase64")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CiphertextBase64 { get; init; }

    public CcEnvelope WithoutCiphertext() => this with { CiphertextBase64 = null };
}
