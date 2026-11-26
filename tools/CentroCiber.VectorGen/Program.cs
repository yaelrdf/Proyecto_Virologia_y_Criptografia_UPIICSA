using System.Text;
using System.Text.Json;
using CentroCiber.Crypto.Algorithms;
using CentroCiber.Crypto.Envelope;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Packaging;

namespace CentroCiber.VectorGen;

/// <summary>
/// Genera los vectores públicos de §16.1 en <c>vectores/EQ08/</c> con una identidad de PRUEBA
/// (nunca la llave real del nodo). Uso: <c>dotnet run --project tools/CentroCiber.VectorGen -- [carpeta]</c>.
/// </summary>
internal static class VectorGenProgram
{
    private static readonly UTF8Encoding Utf8 = new(false);

    public static int Main(string[] args)
    {
        var dir = args.Length > 0 ? args[0] : Path.Combine("vectores", "EQ08");
        Directory.CreateDirectory(dir);
        var clock = TimeProvider.System;
        using var id = NodeIdentity.Create(8, clock);
        Write(dir, "certificado.pem", id.CertificatePem);
        Write(dir, "privada-PRUEBA.pem", id.ExportPrivateKeyPem());

        var none = new Dictionary<string, string>();
        const string sourceIp = "192.168.1.14:5008";

        // HASHSHA
        var hashOriginal = Utf8.GetBytes("Vector de prueba HASHSHA del Equipo 8 — Centro de Ciberseguridad Comunitario.\n");
        var hash = new HashShaAlgorithm().Forward(new ForwardInput(hashOriginal, new Dictionary<string, string> { ["hashAlgorithm"] = "SHA-256" }, none));
        var hashPkg = Build("HASHSHA", hash, hashOriginal, id, sourceIp, clock);
        File.WriteAllBytes(Path.Combine(dir, "HASHSHA_ejemplo.zip"), hashPkg.Zip);
        File.WriteAllBytes(Path.Combine(dir, "HASHSHA_original.txt"), hashOriginal);
        Write(dir, "HASHSHA_secretos.json", "{}\n");

        // HMACSHA256 (clave de prueba de 32 bytes: 0x00..0x1F)
        var key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var secrets = new Dictionary<string, string> { ["key"] = Convert.ToBase64String(key) };
        var hmacOriginal = Utf8.GetBytes("Vector de prueba HMACSHA256 del Equipo 8 — clave de PRUEBA 000102…1F.\n");
        var hmac = new HmacSha256Algorithm().Forward(new ForwardInput(hmacOriginal, none, secrets));
        var hmacPkg = Build("HMACSHA256", hmac, hmacOriginal, id, sourceIp, clock);
        File.WriteAllBytes(Path.Combine(dir, "HMACSHA256_ejemplo.zip"), hmacPkg.Zip);
        File.WriteAllBytes(Path.Combine(dir, "HMACSHA256_original.txt"), hmacOriginal);
        Write(dir, "HMACSHA256_secretos.json", JsonSerializer.Serialize(secrets, ProtocolJson.Options) + "\n");

        // Resultado de ejemplo: inverse de HASHSHA con el original cifrado (CC-ENV-1) para el propio certificado de PRUEBA.
        var packetId = Identifiers.NewUuid();
        var sealedResult = EnvelopeCrypto.Seal(hashOriginal, id.Certificate, id.NodeId, packetId, includeCiphertext: false);
        var result = PackageBuilder.Build(new PackageContent
        {
            PacketType = ProtocolConstants.PacketTypeResult,
            PacketId = packetId,
            RequestId = Identifiers.NewUuid(),
            AlgorithmCode = "HASHSHA",
            AlgorithmName = "SHA-256",
            Operation = ProtocolConstants.OperationInverse,
            PayloadMode = ProtocolConstants.PayloadText,
            OriginalFileName = "HASHSHA_original.txt",
            OriginalSizeBytes = hashOriginal.Length,
            Data = sealedResult.Ciphertext,
            Verification = new Verification { Valid = true, Detail = "Hash coincide" },
            ResultEnvelope = sealedResult.Envelope,
        }, id, sourceIp, clock);
        File.WriteAllBytes(Path.Combine(dir, "HASHSHA_resultado.zip"), result.Zip);

        // §16.1: cadena de firma y texto canónico del paquete HASHSHA.
        Write(dir, "cadena-firma.txt", SignatureChain.Build(hashPkg.Manifest));
        var canonical = CanonicalParameters.CanonicalText(hashPkg.Manifest.PublicParameters);
        Write(dir, "params-canonicos.txt", $"{canonical}\n---\nSHA-256: {CanonicalParameters.Hash(hashPkg.Manifest.PublicParameters)}\n");

        Write(dir, "nombres.json", JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["HASHSHA_ejemplo.zip"] = hashPkg.FileName,
            ["HMACSHA256_ejemplo.zip"] = hmacPkg.FileName,
            ["HASHSHA_resultado.zip"] = result.FileName,
        }, ProtocolJson.Options) + "\n");
        Console.WriteLine($"Vectores generados en {Path.GetFullPath(dir)}");
        Console.WriteLine($"Huella del certificado de PRUEBA: {id.Thumbprint}");
        Console.WriteLine($"Vigencia: {id.Certificate.NotBefore.ToUniversalTime():yyyy-MM-dd HH:mm} → {id.Certificate.NotAfter.ToUniversalTime():yyyy-MM-dd HH:mm} UTC");
        return 0;
    }

    private static BuiltPackage Build(string code, ForwardOutput output, byte[] original, NodeIdentity id, string sourceIp, TimeProvider clock) =>
        PackageBuilder.Build(new PackageContent
        {
            PacketType = ProtocolConstants.PacketTypePackage,
            AlgorithmCode = code,
            AlgorithmName = output.AlgorithmName,
            Operation = ProtocolConstants.OperationForward,
            PayloadMode = ProtocolConstants.PayloadFile,
            OriginalFileName = code + "_original.txt",
            OriginalSizeBytes = original.Length,
            Data = output.Data,
            PublicParameters = output.PublicParameters,
        }, id, sourceIp, clock);

    private static void Write(string dir, string name, string content) => File.WriteAllText(Path.Combine(dir, name), content, Utf8);
}
