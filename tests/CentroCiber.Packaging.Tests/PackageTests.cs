using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;
using Microsoft.Extensions.Time.Testing;

namespace CentroCiber.Packaging.Tests;

public sealed class PackageTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 25, 15, 47, 0, TimeSpan.Zero);
    private readonly FakeTimeProvider clock = new(Now);
    private readonly NodeIdentity eq08 = TestIdentities.Eq08;
    private readonly NodeIdentity eq01 = TestIdentities.Eq01;
    private readonly MemoryReplayGuard replay = new();
    private readonly MemoryTrust trust = new();

    private PackageValidator Validator => new(clock, replay, trust);

    private BuiltPackage HashPackage(byte[]? data = null)
    {
        data ??= "contenido de prueba"u8.ToArray();
        var digest = Hex.Lower(System.Security.Cryptography.SHA256.HashData(data));
        return PackageBuilder.Build(new PackageContent
        {
            PacketType = "package",
            AlgorithmCode = "HASHSHA",
            AlgorithmName = "SHA-256",
            Operation = "forward",
            PayloadMode = "file",
            OriginalFileName = "documento.pdf",
            OriginalSizeBytes = data.Length,
            Data = data,
            PublicParameters = new Dictionary<string, string> { ["hashAlgorithm"] = "SHA-256", ["digestHex"] = digest },
        }, eq08, "192.168.1.14:5008", clock);
    }

    private async Task<string> ErrorOf(byte[] zip, PackageValidationOptions? options = null)
    {
        var ex = await Should.ThrowAsync<ProtocolException>(() => Validator.ValidateAsync(zip, options ?? PackageValidationOptions.Inbox, default));
        return ex.Code;
    }

    [Fact] // Estándar §9.1, §9.3, §9.5, Anexo A.1
    public async Task Built_package_has_three_entries_and_valid_manifest()
    {
        var p = HashPackage();
        ZipTools.Read(p.Zip).Keys.Order().ShouldBe(["certificado.pem", "datos.enc", "manifest.json"]);
        var m = p.Manifest;
        m.Version.ShouldBe("2.0");
        m.SourceNode.ShouldBe("EQ08");
        m.SourceTeam.ShouldBe(8);
        m.ProducerNode.ShouldBe("EQ08");
        m.AlgorithmId.ShouldBe(15);
        m.OperationName.ShouldBe("calcular hash");
        m.OriginalExtension.ShouldBe(".pdf");
        m.ContentType.ShouldBe("application/pdf");
        m.TimestampUtc.ShouldBe("2026-11-25T15:47:00Z");
        m.SignatureAlgorithm.ShouldBe("RSA-PSS-SHA256");
        m.Verification.ShouldBeNull();
        var json = Encoding.UTF8.GetString(ZipTools.Read(p.Zip)["manifest.json"]);
        json.ShouldContain("\"requestId\": null");
        json.ShouldContain("\"resultEnvelope\": null");
        var ok = await Validator.ValidateAsync(p.Zip, PackageValidationOptions.Inbox, default);
        ok.Manifest.PacketId.ShouldBe(m.PacketId);
        ok.SenderPinned.ShouldBeFalse();
    }

    [Fact] // Estándar §9.2
    public void Package_name_follows_nomenclature()
    {
        var p = HashPackage("test"u8.ToArray());
        p.FileName.ShouldBe("EQ08_HASHSHA_20261125_154700_9F86D081.zip");
    }

    [Fact] // Estándar §9.2: result con prefijo RES_
    public void Result_name_has_RES_prefix()
    {
        var r = PackageBuilder.Build(new PackageContent
        {
            PacketType = "result",
            AlgorithmCode = "HASHSHA",
            AlgorithmName = "SHA-256",
            Operation = "inverse",
            PayloadMode = "file",
            OriginalFileName = "a.txt",
            OriginalSizeBytes = 4,
            Data = "test"u8.ToArray(),
            Verification = new Verification { Valid = true, Detail = "Hash coincide" },
        }, eq08, "127.0.0.1:5008", clock);
        r.FileName.ShouldBe("RES_EQ08_HASHSHA_20261125_154700_9F86D081.zip");
        ZipTools.Read(r.Zip).ContainsKey("resultado.enc").ShouldBeTrue();
        r.Manifest.OperationName.ShouldBe("verificar");
        r.Manifest.PublicParametersSha256.ShouldBe(CanonicalParameters.EmptyHash);
    }

    [Fact] // Estándar §9.4
    public async Task Multipart_round_trip_and_tampered_part()
    {
        var (inner, parts) = Multipart.Build([[1, 2, 3], [4, 5], [6]], Now);
        var content = new PackageContent
        {
            PacketType = "package",
            AlgorithmCode = "LAGRANGESHAMIR",
            AlgorithmName = "Shamir GF(256)",
            Operation = "forward",
            PayloadMode = "multipart",
            OriginalFileName = "secreto.bin",
            OriginalSizeBytes = 6,
            Data = inner,
            Parts = parts,
            PublicParameters = new Dictionary<string, string> { ["threshold"] = "2", ["shares"] = "3", ["field"] = "GF(256)" },
        };
        var p = PackageBuilder.Build(content, eq08, "127.0.0.1:5008", clock);
        parts.Select(x => x.Name).ShouldBe(["part-01.bin", "part-02.bin", "part-03.bin"]);
        var ok = await Validator.ValidateAsync(p.Zip, PackageValidationOptions.Inbox, default);
        ok.Parts!.Count.ShouldBe(3);
        ok.Parts[1].ShouldBe(new byte[] { 4, 5 });

        // Parte alterada: el SHA-256 de datos.enc se recalcula y se firma bien, pero la parte no coincide.
        var badParts = parts.ToList();
        badParts[0] = badParts[0] with { Sha256 = new string('0', 64) };
        var bad = PackageBuilder.Build(content with { Parts = badParts }, eq08, "127.0.0.1:5008", clock);
        (await ErrorOf(bad.Zip)).ShouldBe(ErrorCodes.Hash); // Estándar §13.1 #8 (multipart)
    }

    [Fact] // Estándar §9.6
    public async Task Forwarding_keeps_payload_and_producer_and_resigns()
    {
        var original = await Validator.ValidateAsync(HashPackage().Zip, PackageValidationOptions.Inbox, default);
        clock.Advance(TimeSpan.FromMinutes(1));
        var fwd = PackageForwarder.Forward(original, eq01, "192.168.1.21:5001", clock);
        fwd.Manifest.SourceNode.ShouldBe("EQ01");
        fwd.Manifest.SourceTeam.ShouldBe(1);
        fwd.Manifest.ProducerNode.ShouldBe("EQ08");
        fwd.Manifest.PacketId.ShouldNotBe(original.Manifest.PacketId);
        fwd.Manifest.TimestampUtc.ShouldBe("2026-11-25T15:48:00Z");
        fwd.Manifest.EncryptedSha256.ShouldBe(original.Manifest.EncryptedSha256);
        fwd.Manifest.PublicParameters.ShouldBe(original.Manifest.PublicParameters);
        fwd.Manifest.CertificateThumbprintSha256.ShouldBe(eq01.Thumbprint);
        fwd.FileName.ShouldStartWith("EQ01_HASHSHA_");
        var again = await Validator.ValidateAsync(fwd.Zip, PackageValidationOptions.Inbox, default);
        again.Data.ShouldBe(original.Data);
    }

    [Fact] // Estándar §13.1 #1
    public async Task E_SIZE_body_over_50MB() =>
        (await ErrorOf(new byte[ProtocolConstants.MaxBodyBytes + 1])).ShouldBe(ErrorCodes.Size);

    [Fact] // Estándar §13.1 #2
    public async Task E_ZIP_INVALID_not_a_zip() =>
        (await ErrorOf("no soy un zip"u8.ToArray())).ShouldBe(ErrorCodes.ZipInvalid);

    [Fact] // Estándar §13.1 #3: zip con 4 archivos
    public async Task E_ZIP_STRUCTURE_four_files()
    {
        var e = ZipTools.Read(HashPackage().Zip);
        e["extra.txt"] = [1];
        (await ErrorOf(ZipTools.Write(e))).ShouldBe(ErrorCodes.ZipStructure);
    }

    [Theory] // Estándar §13.1 #3: zip-slip, carpetas y ocultos
    [InlineData("../datos.enc")]
    [InlineData("sub/datos.enc")]
    [InlineData("..\\datos.enc")]
    [InlineData(".datos.enc")]
    public async Task E_ZIP_STRUCTURE_paths(string evilName)
    {
        var e = ZipTools.Read(HashPackage().Zip);
        var data = e["datos.enc"];
        e.Remove("datos.enc");
        e[evilName] = data;
        (await ErrorOf(ZipTools.Write(e))).ShouldBe(ErrorCodes.ZipStructure);
    }

    [Fact] // Estándar §13.1 #3: falta un archivo
    public async Task E_ZIP_STRUCTURE_missing_file()
    {
        var e = ZipTools.Read(HashPackage().Zip);
        e.Remove("certificado.pem");
        (await ErrorOf(ZipTools.Write(e))).ShouldBe(ErrorCodes.ZipStructure);
    }

    [Fact] // Estándar §13.1 #4: razón de compresión > 100:1
    public async Task E_ZIP_BOMB_compression_ratio()
    {
        var e = ZipTools.Read(HashPackage().Zip);
        e["datos.enc"] = new byte[5 * 1024 * 1024]; // 5 MB de ceros se comprimen ~1000:1
        (await ErrorOf(ZipTools.Write(e, CompressionLevel.SmallestSize))).ShouldBe(ErrorCodes.ZipBomb);
    }

    [Fact] // Estándar §13.1 #4: datos altamente compresibles propios se guardan sin comprimir y pasan
    public async Task Own_compressible_payload_is_not_a_bomb()
    {
        var p = HashPackage(new byte[3 * 1024 * 1024]);
        (await Validator.ValidateAsync(p.Zip, PackageValidationOptions.Inbox, default)).ShouldNotBeNull();
    }

    [Fact] // Estándar §13.1 #5: manifiesto no JSON
    public async Task E_MANIFEST_not_json()
    {
        var e = ZipTools.Read(HashPackage().Zip);
        e["manifest.json"] = "{no json"u8.ToArray();
        (await ErrorOf(ZipTools.Write(e))).ShouldBe(ErrorCodes.Manifest);
    }

    [Theory] // Estándar §13.1 #5: campos faltantes o con formato inválido
    [InlineData("remove", "packetId")]
    [InlineData("remove", "publicParametersSha256")]
    [InlineData("set", "packetId")]
    [InlineData("set", "sourceNode")]
    [InlineData("set", "timestampUtc")]
    [InlineData("set", "certificateThumbprintSha256")]
    public async Task E_MANIFEST_missing_or_bad_fields(string action, string field)
    {
        var zip = ZipTools.EditManifest(HashPackage().Zip, m =>
        {
            if (action == "remove")
            {
                m.Remove(field);
            }
            else
            {
                m[field] = "MAL";
            }
        });
        (await ErrorOf(zip)).ShouldBe(ErrorCodes.Manifest);
    }

    [Fact] // Estándar §8.5 #1: publicParameters plano de cadenas
    public async Task E_MANIFEST_nested_public_parameters()
    {
        var zip = ZipTools.EditManifest(HashPackage().Zip, m => m["publicParameters"]!["digestHex"] = new JsonObject());
        (await ErrorOf(zip)).ShouldBe(ErrorCodes.Manifest);
    }

    [Fact] // Estándar §13.1 #6
    public async Task E_VERSION()
    {
        var zip = ZipTools.EditManifest(HashPackage().Zip, m => m["version"] = "1.0");
        (await ErrorOf(zip)).ShouldBe(ErrorCodes.Version);
    }

    [Theory] // Estándar §13.1 #7
    [InlineData(16, "HASHSHA")]
    [InlineData(22, "HASHSHA")]
    [InlineData(15, "SHA")]
    public async Task E_ALGORITHM(int id, string code)
    {
        var zip = ZipTools.EditManifest(HashPackage().Zip, m =>
        {
            m["algorithmId"] = id;
            m["algorithmCode"] = code;
        });
        (await ErrorOf(zip)).ShouldBe(ErrorCodes.Algorithm);
    }

    [Fact] // Estándar §13.1 #8: hash alterado
    public async Task E_HASH_tampered_data()
    {
        var e = ZipTools.Read(HashPackage().Zip);
        e["datos.enc"][0] ^= 0xFF;
        (await ErrorOf(ZipTools.Write(e))).ShouldBe(ErrorCodes.Hash);
    }

    [Fact] // Estándar §13.1 #9
    public async Task E_PARAMS_HASH()
    {
        var zip = ZipTools.EditManifest(HashPackage().Zip, m => m["publicParameters"]!["hashAlgorithm"] = "SHA-512");
        (await ErrorOf(zip)).ShouldBe(ErrorCodes.ParamsHash);
    }

    [Fact] // Estándar §13.1 #10: CN distinto de sourceNode
    public async Task E_CERT_cn_mismatch()
    {
        var e = ZipTools.Read(HashPackage().Zip);
        e["certificado.pem"] = Encoding.ASCII.GetBytes(eq01.CertificatePem);
        (await ErrorOf(ZipTools.Write(e))).ShouldBe(ErrorCodes.Cert);
    }

    [Fact] // Estándar §13.1 #10: certificado vencido
    public async Task E_CERT_expired()
    {
        var zip = HashPackage().Zip;
        clock.Advance(TimeSpan.FromDays(400));
        (await ErrorOf(zip, PackageValidationOptions.Inbox with { CheckTimestamp = false })).ShouldBe(ErrorCodes.Cert);
    }

    [Fact] // Estándar §13.1 #11
    public async Task E_CERT_THUMBPRINT()
    {
        var zip = ZipTools.EditManifest(HashPackage().Zip, m => m["certificateThumbprintSha256"] = new string('A', 64));
        (await ErrorOf(zip)).ShouldBe(ErrorCodes.CertThumbprint);
    }

    [Fact] // Estándar §13.1 #12: firma alterada
    public async Task E_SIGNATURE_tampered_signature()
    {
        var zip = ZipTools.EditManifest(HashPackage().Zip, m =>
        {
            var sig = Convert.FromBase64String(m["manifestSignatureBase64"]!.GetValue<string>());
            sig[10] ^= 1;
            m["manifestSignatureBase64"] = Convert.ToBase64String(sig);
        });
        (await ErrorOf(zip)).ShouldBe(ErrorCodes.Signature);
    }

    [Fact] // Estándar §13.1 #12: campo firmado alterado (operation)
    public async Task E_SIGNATURE_tampered_signed_field()
    {
        var zip = ZipTools.EditManifest(HashPackage().Zip, m => m["operation"] = "inverse");
        (await ErrorOf(zip)).ShouldBe(ErrorCodes.Signature);
    }

    [Fact] // Estándar §13.1 #13: timestamp viejo
    public async Task E_TIMESTAMP_old()
    {
        var zip = HashPackage().Zip;
        clock.Advance(TimeSpan.FromMinutes(11));
        (await ErrorOf(zip)).ShouldBe(ErrorCodes.Timestamp);
    }

    [Fact] // Estándar §13.1 #13: timestamp en el futuro
    public async Task E_TIMESTAMP_future()
    {
        var future = new FakeTimeProvider(Now.AddMinutes(11));
        var data = "x"u8.ToArray();
        var zip = PackageBuilder.Build(new PackageContent
        {
            PacketType = "package",
            AlgorithmCode = "HASHSHA",
            AlgorithmName = "SHA-256",
            Operation = "forward",
            PayloadMode = "text",
            OriginalFileName = "mensaje.txt",
            OriginalSizeBytes = 1,
            Data = data,
        }, eq08, "127.0.0.1:5008", future).Zip;
        (await ErrorOf(zip)).ShouldBe(ErrorCodes.Timestamp);
    }

    [Fact] // Estándar §13.1 #13: dentro de la ventana
    public async Task Timestamp_within_window_is_accepted()
    {
        var zip = HashPackage().Zip;
        clock.Advance(TimeSpan.FromMinutes(9));
        (await Validator.ValidateAsync(zip, PackageValidationOptions.Inbox, default)).ShouldNotBeNull();
    }

    [Fact] // Estándar §13.1 #14: packetId repetido
    public async Task E_DUPLICATE_packet_id()
    {
        var zip = HashPackage().Zip;
        await Validator.ValidateAsync(zip, PackageValidationOptions.Inbox, default);
        (await ErrorOf(zip)).ShouldBe(ErrorCodes.Duplicate);
    }

    [Fact] // Estándar §13.1 nota: huella fijada distinta
    public async Task E_CERT_UNTRUSTED_pinned_mismatch()
    {
        trust.Pinned["EQ08"] = eq01.Thumbprint;
        (await ErrorOf(HashPackage().Zip)).ShouldBe(ErrorCodes.CertUntrusted);
    }

    [Fact] // Estándar §13.1 nota: remitente fijado con la misma huella
    public async Task Pinned_sender_is_reported()
    {
        trust.Pinned["EQ08"] = eq08.Thumbprint;
        (await Validator.ValidateAsync(HashPackage().Zip, PackageValidationOptions.Inbox, default)).SenderPinned.ShouldBeTrue();
    }

    [Fact] // ADR 0005: inverse no aplica #13/#14 al paquete embebido
    public async Task Inverse_validation_skips_timestamp_and_replay()
    {
        var zip = HashPackage().Zip;
        clock.Advance(TimeSpan.FromDays(2));
        await Validator.ValidateAsync(zip, PackageValidationOptions.ForInverse, default);
        await Validator.ValidateAsync(zip, PackageValidationOptions.ForInverse, default);
    }

    [Fact] // Interfaz: validación paso a paso
    public async Task Report_lists_steps_and_failure()
    {
        var e = ZipTools.Read(HashPackage().Zip);
        e["datos.enc"][0] ^= 0xFF;
        var report = await Validator.ValidateWithReportAsync(ZipTools.Write(e), PackageValidationOptions.Inbox, default);
        report.IsValid.ShouldBeFalse();
        report.Steps.Count(s => s.Passed).ShouldBe(7);
        report.Steps[^1].Number.ShouldBe(8);
        report.Steps[^1].Code.ShouldBe(ErrorCodes.Hash);
        var ok = await Validator.ValidateWithReportAsync(HashPackage().Zip, PackageValidationOptions.Inbox, default);
        ok.Steps.Select(s => s.Number).Distinct().Count().ShouldBe(14);
    }

    [Fact] // Estándar §9.5: campos desconocidos se ignoran
    public async Task Unknown_manifest_fields_are_ignored()
    {
        var zip = ZipTools.EditManifest(HashPackage().Zip, m => m["extensionFutura"] = "x");
        (await Validator.ValidateAsync(zip, PackageValidationOptions.Inbox, default)).ShouldNotBeNull();
    }

    [Fact] // ADR 0014: otro nodo omite los campos anulables (caso real de EQ01: sin requestId ni parts)
    public async Task Missing_nullable_fields_are_treated_as_null()
    {
        var zip = ZipTools.EditManifest(HashPackage().Zip, m =>
        {
            m.Remove("requestId");
            m.Remove("parts");
            m.Remove("keyRef");
            m.Remove("verification");
            m.Remove("resultEnvelope");
        }, eq08);
        var ok = await Validator.ValidateAsync(zip, PackageValidationOptions.Inbox, default);
        ok.Manifest.RequestId.ShouldBeNull();
        ok.Manifest.Parts.ShouldBeNull();
        ok.Manifest.KeyRef.ShouldBeNull();
    }

    [Fact] // ADR 0014: un result sin verification es válido como paquete
    public async Task Result_without_optional_fields_is_accepted()
    {
        var r = PackageBuilder.Build(new PackageContent
        {
            PacketType = "result",
            AlgorithmCode = "HASHSHA",
            AlgorithmName = "SHA-256",
            Operation = "inverse",
            PayloadMode = "file",
            OriginalFileName = "a.txt",
            OriginalSizeBytes = 4,
            Data = "test"u8.ToArray(),
        }, eq08, "127.0.0.1:5008", clock);
        var zip = ZipTools.EditManifest(r.Zip, m =>
        {
            m.Remove("verification");
            m.Remove("resultEnvelope");
            m.Remove("requestId");
        }, eq08);
        (await Validator.ValidateAsync(zip, PackageValidationOptions.Inbox, default)).Manifest.Verification.ShouldBeNull();
    }

    [Fact] // §9.4: multipart sin parts sigue siendo E-MANIFEST aunque parts sea anulable
    public async Task Multipart_without_parts_is_rejected()
    {
        var (inner, parts) = Multipart.Build([[1, 2]], Now);
        var p = PackageBuilder.Build(new PackageContent
        {
            PacketType = "package",
            AlgorithmCode = "LAGRANGESHAMIR",
            AlgorithmName = "Shamir",
            Operation = "forward",
            PayloadMode = "multipart",
            OriginalFileName = "s.bin",
            OriginalSizeBytes = 2,
            Data = inner,
            Parts = parts,
        }, eq08, "127.0.0.1:5008", clock);
        var zip = ZipTools.EditManifest(p.Zip, m => m.Remove("parts"), eq08);
        (await ErrorOf(zip)).ShouldBe(ErrorCodes.Manifest);
    }

    [Fact] // ADR 0015: AESGCM/CHACHA20 usan AAD = packetId; al reenviar se conserva
    public async Task Forwarding_aad_bound_algorithm_keeps_packet_id()
    {
        var aes = PackageBuilder.Build(new PackageContent
        {
            PacketType = "package",
            AlgorithmCode = "AESGCM",
            AlgorithmName = "AES-256-GCM",
            Operation = "forward",
            PayloadMode = "text",
            OriginalFileName = "m.txt",
            OriginalSizeBytes = 3,
            Data = [1, 2, 3],
            PublicParameters = new Dictionary<string, string> { ["keySizeBits"] = "256", ["nonceBase64"] = "AAAAAAAAAAAAAAAA", ["tagBase64"] = "AAAAAAAAAAAAAAAAAAAAAA==" },
        }, eq01, "127.0.0.1:5001", clock);
        var original = await Validator.ValidateAsync(aes.Zip, PackageValidationOptions.Inbox, default);
        var fwd = PackageForwarder.Forward(original, eq08, "127.0.0.1:5008", clock);
        fwd.Manifest.PacketId.ShouldBe(aes.Manifest.PacketId);
        fwd.Manifest.SourceNode.ShouldBe("EQ08");
        fwd.Manifest.ProducerNode.ShouldBe("EQ01");
        (await new PackageValidator(clock, new MemoryReplayGuard(), trust).ValidateAsync(fwd.Zip, PackageValidationOptions.Inbox, default))
            .Manifest.CertificateThumbprintSha256.ShouldBe(eq08.Thumbprint);
    }
}
