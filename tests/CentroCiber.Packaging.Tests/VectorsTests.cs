using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CentroCiber.Crypto.Algorithms;
using CentroCiber.Crypto.Envelope;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;
using Microsoft.Extensions.Time.Testing;

namespace CentroCiber.Packaging.Tests;

/// <summary>Estándar §16.1 y §16.2: los vectores publicados se validan con el validador de recepción.</summary>
public class VectorsTests
{
    private static readonly string Dir = Path.Combine(RepoPaths.Root, "vectores", "EQ08");

    private static async Task<ValidatedPackage> ValidateAsync(string name)
    {
        var zip = await File.ReadAllBytesAsync(Path.Combine(Dir, name));
        using var archive = ZipSafety.Open(zip);
        var m = PackageValidator.ParseManifest(ZipSafety.ReadAll(archive.GetEntry("manifest.json")!));
        Identifiers.TryParseTimestamp(m.TimestampUtc, out var ts).ShouldBeTrue();
        // Se valida en el instante del vector (incluida la ventana ±10 min) para que la prueba no caduque.
        var validator = new PackageValidator(new FakeTimeProvider(ts), new MemoryReplayGuard(), new MemoryTrust());
        return await validator.ValidateAsync(zip, PackageValidationOptions.Inbox, default);
    }

    [Theory]
    [InlineData("HASHSHA_ejemplo.zip")]
    [InlineData("HMACSHA256_ejemplo.zip")]
    [InlineData("HASHSHA_resultado.zip")]
    public async Task Vector_packages_pass_all_14_checks(string name) =>
        (await ValidateAsync(name)).Manifest.SourceNode.ShouldBe("EQ08");

    [Fact]
    public async Task Hmac_vector_verifies_with_published_secret()
    {
        var p = await ValidateAsync("HMACSHA256_ejemplo.zip");
        var secrets = JsonSerializer.Deserialize<Dictionary<string, string>>(await File.ReadAllTextAsync(Path.Combine(Dir, "HMACSHA256_secretos.json")))!;
        var r = new HmacSha256Algorithm().Inverse(new InverseInput(p.Data, p.Manifest.PublicParameters, new Dictionary<string, string>(), secrets));
        r.Valid.ShouldBe(true);
        r.Original.ShouldBe(await File.ReadAllBytesAsync(Path.Combine(Dir, "HMACSHA256_original.txt")));
    }

    [Fact]
    public async Task Chain_canonical_text_and_result_envelope_match()
    {
        var p = await ValidateAsync("HASHSHA_ejemplo.zip");
        (await File.ReadAllTextAsync(Path.Combine(Dir, "cadena-firma.txt"))).ShouldBe(SignatureChain.Build(p.Manifest));
        (await File.ReadAllTextAsync(Path.Combine(Dir, "params-canonicos.txt"))).ShouldStartWith(CanonicalParameters.CanonicalText(p.Manifest.PublicParameters) + "\n---\n");

        using var id = NodeIdentity.FromPem(await File.ReadAllTextAsync(Path.Combine(Dir, "certificado.pem")),
            await File.ReadAllTextAsync(Path.Combine(Dir, "privada-PRUEBA.pem")));
        var r = await ValidateAsync("HASHSHA_resultado.zip");
        EnvelopeCrypto.OpenDetached(r.Manifest.ResultEnvelope!, r.Data, id, r.Manifest.PacketId)
            .ShouldBe(await File.ReadAllBytesAsync(Path.Combine(Dir, "HASHSHA_original.txt")));
        Hex.Lower(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalParameters.CanonicalText(p.Manifest.PublicParameters))))
            .ShouldBe(p.Manifest.PublicParametersSha256);
    }
}
