using System.Text.Json;
using CentroCiber.Crypto.Envelope;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Packaging.Tests;

/// <summary>Puente .NET ↔ Python (cryptography). Estándar §8, §16.2 “Sobre CC-ENV-1 interoperable en ambos sentidos”.</summary>
public class InteropBridgeTests
{
    [Fact] // .NET → Python: certificado, firma, hash canónico, sobre y paquetes
    public void Python_verifies_artifacts_produced_by_dotnet()
    {
        var dir = InteropFixtures.Directory;
        var (code, output) = PythonRunner.Run(
            ["-m", "pytest", Path.Combine(RepoPaths.Root, "tests", "interop"), "-q", "-p", "no:cacheprovider"],
            new Dictionary<string, string> { ["CC_INTEROP_DIR"] = dir });
        code.ShouldBe(0, output);
        output.ShouldContain("passed");
    }

    [Fact] // Python → .NET: sobre creado con cryptography se abre en .NET
    public void Dotnet_opens_envelope_created_by_python()
    {
        var dir = InteropFixtures.Directory;
        var aad = Identifiers.NewUuid();
        var input = Path.Combine(dir, "py-entrada.bin");
        var output = Path.Combine(dir, "py-sobre.json");
        File.WriteAllBytes(input, "secreto creado en Python ✓"u8.ToArray());
        var (code, log) = PythonRunner.Run([
            Path.Combine(RepoPaths.Root, "tests", "interop", "make_envelope.py"),
            Path.Combine(dir, "certificado.pem"), "EQ08", aad, input, output]);
        code.ShouldBe(0, log);
        var env = JsonSerializer.Deserialize<CcEnvelope>(File.ReadAllText(output))!;
        EnvelopeCrypto.Open(env, InteropFixtures.Identity, aad).ShouldBe(File.ReadAllBytes(input));
    }
}
