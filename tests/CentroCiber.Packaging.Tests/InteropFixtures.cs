using System.Text;
using System.Text.Json;
using CentroCiber.Crypto.Envelope;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Crypto.Signing;

namespace CentroCiber.Packaging.Tests;

/// <summary>
/// Escribe los artefactos producidos por .NET que el código Python independiente verifica
/// (carpeta <c>artifacts/interop</c>, ignorada por git).
/// </summary>
public static class InteropFixtures
{
    private static readonly Lazy<string> Generated = new(Generate);

    public static string Directory => Generated.Value;

    public static NodeIdentity Identity { get; } = NodeIdentity.Create(8, TimeProvider.System);

    private static string Generate()
    {
        var dir = Path.Combine(RepoPaths.Root, "artifacts", "interop");
        if (System.IO.Directory.Exists(dir))
        {
            System.IO.Directory.Delete(dir, true);
        }

        System.IO.Directory.CreateDirectory(dir);
        var id = Identity;
        Write(dir, "certificado.pem", id.CertificatePem);
        Write(dir, "privada-PRUEBA.pem", id.ExportPrivateKeyPem());
        Write(dir, "huella.txt", id.Thumbprint);

        var chain = "2.0|package|550e8400-e29b-41d4-a716-446655440000|EQ08|EQ08|HASHSHA|forward|2026-11-25T15:47:00Z|"
            + "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08|" + CanonicalParameters.EmptyHash + "|" + id.Thumbprint;
        Write(dir, "cadena-firma.txt", chain);
        Write(dir, "firma.b64", RsaPss.SignBase64(id.PrivateKey, Encoding.UTF8.GetBytes(chain)));

        var parameters = new Dictionary<string, string>
        {
            ["hashAlgorithm"] = "SHA-256",
            ["digestHex"] = "ab12",
            ["ñandú"] = "sí",
            ["Zeta"] = "z",
        };
        Write(dir, "params.json", JsonSerializer.Serialize(parameters, ProtocolJson.Options));
        Write(dir, "params-canonicos.txt", CanonicalParameters.CanonicalText(parameters));
        Write(dir, "params-hash.txt", CanonicalParameters.Hash(parameters));

        var aad = Identifiers.NewUuid();
        var plaintext = "{\"key\":\"q83vEjRWeJA=\"} — sobre de prueba"u8.ToArray();
        var envelope = EnvelopeCrypto.Seal(plaintext, id.Certificate, id.NodeId, aad).Envelope;
        Write(dir, "sobre.json", JsonSerializer.Serialize(envelope, ProtocolJson.Options));
        Write(dir, "sobre-aad.txt", aad);
        File.WriteAllBytes(Path.Combine(dir, "sobre-esperado.txt"), plaintext);

        foreach (var (name, bytes) in PackageFixtures.Build(id))
        {
            var path = Path.Combine(dir, "paquetes", name);
            System.IO.Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path, bytes);
        }

        return dir;
    }

    private static void Write(string dir, string name, string content) =>
        File.WriteAllText(Path.Combine(dir, name), content, new UTF8Encoding(false));
}

