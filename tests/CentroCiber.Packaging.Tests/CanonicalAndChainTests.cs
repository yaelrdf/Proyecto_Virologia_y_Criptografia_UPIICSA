using System.Security.Cryptography;
using System.Text;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Packaging.Tests;

public class CanonicalAndChainTests
{
    [Fact] // Estándar §8.5 (ejemplo literal)
    public void Canonical_text_matches_standard_example()
    {
        var p = new Dictionary<string, string> { ["hashAlgorithm"] = "SHA-256", ["digestHex"] = "ab12" };
        CanonicalParameters.CanonicalText(p).ShouldBe("digestHex=ab12\nhashAlgorithm=SHA-256");
        CanonicalParameters.Hash(p).ShouldBe(Hex.Lower(SHA256.HashData(Encoding.UTF8.GetBytes("digestHex=ab12\nhashAlgorithm=SHA-256"))));
    }

    [Fact] // Estándar §8.5 #6
    public void Empty_parameters_hash_the_empty_string() =>
        CanonicalParameters.Hash(new Dictionary<string, string>()).ShouldBe(CanonicalParameters.EmptyHash);

    [Fact] // Estándar §8.5 #2: orden ordinal de bytes UTF-8, sensible a mayúsculas
    public void Keys_are_sorted_by_utf8_bytes()
    {
        var p = new Dictionary<string, string> { ["b"] = "1", ["B"] = "2", ["a"] = "3", ["ñ"] = "4", ["\U0001F600"] = "5", ["�"] = "6" };
        // UTF-8: 'B'(42) < 'a'(61) < 'b'(62) < 'ñ'(C3 B1) < U+FFFD (EF BF BD) < U+1F600 (F0 9F 98 80)
        CanonicalParameters.CanonicalText(p).ShouldBe("B=2\na=3\nb=1\nñ=4\n�=6\n\U0001F600=5");
    }

    [Fact] // Estándar §8.4 (ejemplo literal)
    public void Signature_chain_matches_standard_example()
    {
        var m = new Manifest
        {
            Version = "2.0",
            PacketType = "package",
            PacketId = "550e8400-e29b-41d4-a716-446655440000",
            SourceNode = "EQ08",
            SourceTeam = 8,
            SourceIp = "192.168.1.14:5008",
            ProducerNode = "EQ08",
            TimestampUtc = "2026-11-25T15:47:00Z",
            AlgorithmId = 15,
            AlgorithmCode = "HASHSHA",
            AlgorithmName = "SHA-256",
            Operation = "forward",
            OperationName = "calcular hash",
            PayloadMode = "file",
            OriginalFileName = "documento.pdf",
            OriginalExtension = ".pdf",
            OriginalSizeBytes = 14820,
            ContentType = "application/pdf",
            EncryptedSha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            EncryptedSizeBytes = 14820,
            PublicParameters = new Dictionary<string, string>(),
            PublicParametersSha256 = "3b2c...e1",
            CertificateThumbprintSha256 = "A1B2C3D4E5F6...",
            SignatureAlgorithm = "RSA-PSS-SHA256",
            ManifestSignatureBase64 = string.Empty,
        };
        SignatureChain.Build(m).ShouldBe(
            "2.0|package|550e8400-e29b-41d4-a716-446655440000|EQ08|EQ08|HASHSHA|forward|2026-11-25T15:47:00Z|9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08|3b2c...e1|A1B2C3D4E5F6...");
    }
}
