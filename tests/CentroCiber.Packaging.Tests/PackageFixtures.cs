using System.Text;
using CentroCiber.Crypto.Algorithms;
using CentroCiber.Crypto.Envelope;
using CentroCiber.Crypto.Identity;

namespace CentroCiber.Packaging.Tests;

/// <summary>Paquetes generados por .NET para que Python los verifique (test_packages.py).</summary>
public static class PackageFixtures
{
    public const string HmacKeyBase64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    public static IEnumerable<(string Name, byte[] Bytes)> Build(NodeIdentity identity)
    {
        var clock = TimeProvider.System;
        var original = Encoding.UTF8.GetBytes("Mensaje de interoperabilidad — EQ08 ✓");
        var none = new Dictionary<string, string>();

        var hash = new HashShaAlgorithm().Forward(new ForwardInput(original, none, none));
        yield return ("hashsha.zip", Package("HASHSHA", hash, original, identity, clock).Zip);

        var hmac = new HmacSha256Algorithm().Forward(new ForwardInput(original, none,
            new Dictionary<string, string> { ["key"] = HmacKeyBase64 }));
        yield return ("hmacsha256.zip", Package("HMACSHA256", hmac, original, identity, clock).Zip);

        // result: el original va cifrado con CC-ENV-1 para el propio certificado (AAD = packetId del result).
        var packetId = Crypto.Protocol.Identifiers.NewUuid();
        var sealedResult = EnvelopeCrypto.Seal(original, identity.Certificate, identity.NodeId, packetId, includeCiphertext: false);
        var result = PackageBuilder.Build(new PackageContent
        {
            PacketType = "result",
            PacketId = packetId,
            RequestId = Crypto.Protocol.Identifiers.NewUuid(),
            AlgorithmCode = "HASHSHA",
            AlgorithmName = "SHA-256",
            Operation = "inverse",
            PayloadMode = "text",
            OriginalFileName = "mensaje.txt",
            OriginalSizeBytes = original.Length,
            Data = sealedResult.Ciphertext,
            Verification = new Verification { Valid = true, Detail = "Hash coincide" },
            ResultEnvelope = sealedResult.Envelope,
        }, identity, "127.0.0.1:5008", clock);
        yield return ("result.zip", result.Zip);

        var (inner, parts) = Multipart.Build([[1, 2, 3], Encoding.UTF8.GetBytes("parte dos")], clock.GetUtcNow());
        yield return ("multipart.zip", PackageBuilder.Build(new PackageContent
        {
            PacketType = "package",
            AlgorithmCode = "LAGRANGESHAMIR",
            AlgorithmName = "Shamir GF(256)",
            Operation = "forward",
            PayloadMode = "multipart",
            OriginalFileName = "secreto.bin",
            OriginalSizeBytes = 12,
            Data = inner,
            Parts = parts,
            PublicParameters = new Dictionary<string, string> { ["threshold"] = "2", ["shares"] = "2", ["field"] = "GF(256)" },
        }, identity, "127.0.0.1:5008", clock).Zip);

    }

    private static BuiltPackage Package(string code, ForwardOutput output, byte[] original, NodeIdentity identity, TimeProvider clock) =>
        PackageBuilder.Build(new PackageContent
        {
            PacketType = "package",
            AlgorithmCode = code,
            AlgorithmName = output.AlgorithmName,
            Operation = "forward",
            PayloadMode = "text",
            OriginalFileName = "mensaje.txt",
            OriginalSizeBytes = original.Length,
            Data = output.Data,
            PublicParameters = output.PublicParameters,
        }, identity, "127.0.0.1:5008", clock);
}
