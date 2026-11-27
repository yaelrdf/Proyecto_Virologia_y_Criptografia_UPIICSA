using System.Net;
using System.Text;
using System.Text.Json;
using CentroCiber.Crypto.Envelope;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Packaging;
using CentroCiber.Packaging.Contracts;

namespace CentroCiber.Api.Tests;

public sealed class ProviderApiTests : IDisposable
{
    private readonly NodeFactory factory = new();
    private readonly HttpClient client;

    public ProviderApiTests() => client = factory.CreateClient();

    public void Dispose()
    {
        client.Dispose();
        factory.Dispose();
    }

    private Task<ValidatedPackage> ValidateAsync(byte[] zip) =>
        new PackageValidator(TimeProvider.System, new Packaging.Tests.MemoryReplayGuard(), new Packaging.Tests.MemoryTrust())
            .ValidateAsync(zip, PackageValidationOptions.Inbox, default);

    [Fact] // Estándar §10.3
    public async Task Status_includes_algorithms_https_and_thumbprint()
    {
        var status = await client.GetFromJsonAsync<StatusResponse>("/api/status");
        status!.NodeId.ShouldBe("EQ08");
        status.HttpsPort.ShouldBe(5108);
        status.Algorithms.Select(a => a.AlgorithmCode).ShouldBe(["HASHSHA", "HMACSHA256"]);
        status.CertificateThumbprintSha256.ShouldBe(factory.Node().Identity.Thumbprint);
        Identifiers.IsTimestamp(status.ServerTimeUtc).ShouldBeTrue();
        status.SupportedProtocolVersions.ShouldBe(["2.0"]); // extensión compatible con EQ06
        status.NodeVersion.ShouldBe("1.1.0");
    }

    [Fact] // Compatibilidad: el status de EQ06 trae campos extra (role, endpoint, certificateThumbprint) y perfiles con "notes"
    public void Foreign_status_and_profile_extensions_are_ignored()
    {
        var status = JsonSerializer.Deserialize<StatusResponse>("""
            {"nodeId":"EQ06","teamNumber":6,"protocolVersion":"2.0","status":"online","acceptingPackages":true,"httpPort":5006,"httpsPort":null,
             "algorithms":[{"algorithmId":11,"algorithmCode":"LSBSTEGO"}],"certificateThumbprintSha256":"AA","serverTimeUtc":"2026-11-27T10:00:00Z",
             "certificateThumbprint":"AA","supportedProtocolVersions":["1.0","2.0"],"role":"Initial","endpoint":"http://10.0.0.6:5006"}
            """)!;
        status.SupportedProtocolVersions.ShouldBe(["1.0", "2.0"]);
        var profile = JsonSerializer.Deserialize<AlgorithmsResponse>("""
            {"nodeId":"EQ06","algorithms":[{"algorithmId":11,"algorithmCode":"LSBSTEGO","variants":["LSB-1BIT-PNG"],
             "operations":{"forward":{"name":"ocultar","inputs":["payload","cover"]},"inverse":{"name":"extraer","inputs":["package"]}},
             "secretParameters":[{"name":"password","type":"text","optional":true,"requiredFor":[]}],"options":[],
             "publicParameters":["imageFormat"],"payloadModes":["text"],"maxPayloadBytes":52428800,"notes":"Portadora PNG."}]}
            """)!;
        profile.Algorithms[0].Notes.ShouldBe("Portadora PNG.");
        profile.Algorithms[0].Operations["forward"].Inputs.ShouldContain("cover");
    }

    [Fact] // Estándar §10.1: encabezados X-CC-* en las respuestas de la API
    public async Task Responses_carry_protocol_headers()
    {
        var r = await client.GetAsync(new Uri("/api/status", UriKind.Relative));
        r.Headers.GetValues("X-CC-Node").Single().ShouldBe("EQ08");
        r.Headers.GetValues("X-CC-Protocol").Single().ShouldBe("2.0");
    }

    [Fact] // Estándar §10.2 y §7
    public async Task Certificate_is_single_pem()
    {
        var r = await client.GetAsync(new Uri("/api/certificate", UriKind.Relative));
        r.Content.Headers.ContentType!.MediaType.ShouldBe("application/x-pem-file");
        var pem = await r.Content.ReadAsStringAsync();
        pem.ShouldStartWith("-----BEGIN CERTIFICATE-----");
        pem.Split("BEGIN CERTIFICATE").Length.ShouldBe(2);
    }

    [Fact] // Estándar §10.4
    public async Task Algorithms_profile_matches_standard_example()
    {
        var json = await client.GetStringAsync(new Uri("/api/algorithms", UriKind.Relative));
        var profile = JsonSerializer.Deserialize<AlgorithmsResponse>(json)!;
        profile.NodeId.ShouldBe("EQ08");
        var hmac = profile.Algorithms.Single(a => a.AlgorithmCode == "HMACSHA256");
        hmac.AlgorithmId.ShouldBe(16);
        hmac.Variants.ShouldBe(["HMAC-SHA256"]);
        hmac.SecretParameters.Single().MinBytes.ShouldBe(32);
        hmac.Operations["forward"].Name.ShouldBe("calcular MAC");
        hmac.Operations["inverse"].Inputs.ShouldBe(["package"]);
        hmac.MaxPayloadBytes.ShouldBe(52428800);
        profile.Algorithms.Single(a => a.AlgorithmCode == "HASHSHA").Variants.ShouldBe(["SHA-256", "SHA-512"]);
    }

    [Fact] // Estándar §12 #8
    public async Task Keys_returns_E_KEY_NOT_FOUND()
    {
        var r = await client.GetAsync(new Uri("/api/keys/EQ08-KEY-1f0c2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b", UriKind.Relative));
        r.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.KeyNotFound);
    }

    [Fact] // Estándar §10.6, §4.3 HASHSHA forward
    public async Task Forward_HASHSHA_returns_signed_package()
    {
        var req = ApiHelpers.Request(factory, Ids.Eq03, "HASHSHA", "forward", options: new() { ["hashAlgorithm"] = "SHA-512" });
        var r = await client.PostCryptoAsync("forward", req, "hola"u8.ToArray());
        r.StatusCode.ShouldBe(HttpStatusCode.OK);
        r.Content.Headers.ContentType!.MediaType.ShouldBe("application/zip");
        r.Content.Headers.ContentDisposition!.FileName!.ShouldStartWith("EQ08_HASHSHA_");
        var p = await ValidateAsync(await r.Content.ReadAsByteArrayAsync());
        p.Manifest.SourceNode.ShouldBe("EQ08");
        p.Manifest.ProducerNode.ShouldBe("EQ08");
        p.Manifest.RequestId.ShouldBe(req.Request.RequestId);
        p.Manifest.AlgorithmName.ShouldBe("SHA-512");
        p.Manifest.PublicParameters["digestHex"].ShouldBe(Hex.Lower(System.Security.Cryptography.SHA512.HashData("hola"u8)));
        p.Data.ShouldBe("hola"u8.ToArray());
    }

    [Fact] // Estándar §10.6, §4.3 HMACSHA256 forward + inverse (Anexo A.3)
    public async Task Forward_and_inverse_HMAC_with_envelope()
    {
        var secrets = new Dictionary<string, string> { ["key"] = ApiHelpers.HmacKey };
        var fwd = await client.PostCryptoAsync("forward", ApiHelpers.Request(factory, Ids.Eq03, "HMACSHA256", "forward", secrets), "contrato"u8.ToArray());
        fwd.StatusCode.ShouldBe(HttpStatusCode.OK);
        var package = await fwd.Content.ReadAsByteArrayAsync();
        var manifestText = Encoding.UTF8.GetString(Packaging.Tests.ZipTools.Read(package)["manifest.json"]);
        manifestText.ShouldNotContain(ApiHelpers.HmacKey); // §9.5: nunca secretos en el manifiesto

        var inv = ApiHelpers.Request(factory, Ids.Eq03, "HMACSHA256", "inverse", secrets);
        var r = await client.PostCryptoAsync("inverse", inv, package: package);
        r.StatusCode.ShouldBe(HttpStatusCode.OK);
        r.Content.Headers.ContentDisposition!.FileName!.ShouldStartWith("RES_EQ08_HMACSHA256_");
        var result = await ValidateAsync(await r.Content.ReadAsByteArrayAsync());
        result.Manifest.PacketType.ShouldBe("result");
        result.Manifest.Verification!.Valid.ShouldBeTrue();
        result.Manifest.Verification.Detail.ShouldBe("HMAC coincide");
        result.Manifest.RequestId.ShouldBe(inv.Request.RequestId);
        result.Manifest.ResultEnvelope!.RecipientNode.ShouldBe("EQ03");
        EnvelopeCrypto.OpenDetached(result.Manifest.ResultEnvelope, result.Data, Ids.Eq03, result.Manifest.PacketId)
            .ShouldBe("contrato"u8.ToArray());
    }

    [Fact] // Plan §2.1: valid=false es 200 con veredicto
    public async Task Inverse_HMAC_with_wrong_key_returns_valid_false()
    {
        var fwd = await client.PostCryptoAsync("forward",
            ApiHelpers.Request(factory, Ids.Eq03, "HMACSHA256", "forward", new() { ["key"] = ApiHelpers.HmacKey }), "x"u8.ToArray());
        var wrong = Convert.ToBase64String(new byte[32]);
        var r = await client.PostCryptoAsync("inverse",
            ApiHelpers.Request(factory, Ids.Eq03, "HMACSHA256", "inverse", new() { ["key"] = wrong }), package: await fwd.Content.ReadAsByteArrayAsync());
        r.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await ValidateAsync(await r.Content.ReadAsByteArrayAsync())).Manifest.Verification!.Valid.ShouldBeFalse();
    }

    [Fact] // Estándar §4.3 HASHSHA inverse sobre un paquete producido por otro nodo
    public async Task Inverse_HASHSHA_of_foreign_package()
    {
        var package = ApiHelpers.HashPackage(Ids.Eq05).Zip;
        var r = await client.PostCryptoAsync("inverse", ApiHelpers.Request(factory, Ids.Eq03, "HASHSHA", "inverse"), package: package);
        r.StatusCode.ShouldBe(HttpStatusCode.OK);
        var result = await ValidateAsync(await r.Content.ReadAsByteArrayAsync());
        result.Manifest.Verification!.Valid.ShouldBeTrue();
        result.Manifest.PublicParameters.ShouldBeEmpty(); // ADR 0007
        EnvelopeCrypto.OpenDetached(result.Manifest.ResultEnvelope!, result.Data, Ids.Eq03, result.Manifest.PacketId)
            .ShouldBe("hola EQ08"u8.ToArray());
    }

    [Fact] // ADR 0005: el mismo paquete se puede invertir dos veces
    public async Task Same_package_can_be_inverted_twice()
    {
        var package = ApiHelpers.HashPackage(Ids.Eq05).Zip;
        for (var i = 0; i < 2; i++)
        {
            var r = await client.PostCryptoAsync("inverse", ApiHelpers.Request(factory, Ids.Eq03, "HASHSHA", "inverse"), package: package);
            r.StatusCode.ShouldBe(HttpStatusCode.OK);
        }
    }

    [Fact] // Estándar §13.2 #3
    public async Task E_REQUEST_SIGNATURE()
    {
        var req = ApiHelpers.Request(factory, Ids.Eq03, "HASHSHA", "forward");
        var tampered = req with { RequestBytes = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(req.RequestBytes).Replace("documento", "Documento", StringComparison.Ordinal)) };
        var r = await client.PostCryptoAsync("forward", tampered, "x"u8.ToArray());
        r.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.RequestSignature);
    }

    [Fact] // Estándar §13.2 #2: CN del certificado ≠ requesterNode
    public async Task E_CERT_requester_cn_mismatch()
    {
        var req = ApiHelpers.Request(factory, Ids.Eq03, "HASHSHA", "forward") with { RequesterCertificatePem = Ids.Eq05.CertificatePem };
        var r = await client.PostCryptoAsync("forward", req, "x"u8.ToArray());
        r.StatusCode.ShouldBe((HttpStatusCode)422);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.Cert);
    }

    [Fact] // Estándar §13.2 #4
    public async Task E_REQUEST_wrong_target()
    {
        var req = ApiHelpers.Request(factory, Ids.Eq03, "HASHSHA", "forward", edit: s => s with { TargetNode = "EQ01" });
        var r = await client.PostCryptoAsync("forward", req, "x"u8.ToArray());
        r.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.Request);
    }

    [Fact] // Estándar §10.6: partes faltantes
    public async Task E_REQUEST_missing_payload()
    {
        var r = await client.PostCryptoAsync("forward", ApiHelpers.Request(factory, Ids.Eq03, "HASHSHA", "forward"));
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.Request);
    }

    [Fact] // Estándar §13.2 (versión)
    public async Task E_VERSION_request()
    {
        var req = ApiHelpers.Request(factory, Ids.Eq03, "HASHSHA", "forward", edit: s => s with { Version = "1.0" });
        (await (await client.PostCryptoAsync("forward", req, "x"u8.ToArray())).ProblemCodeAsync()).ShouldBe(ErrorCodes.Version);
    }

    [Fact] // Estándar §13.2 #5: timestamp
    public async Task E_TIMESTAMP_request()
    {
        var old = ApiHelpers.Request(factory, Ids.Eq03, "HASHSHA", "forward");
        var stale = Packaging.Client.CryptoRequestBuilder.Sign(Ids.Eq03, old.Request with { TimestampUtc = "2020-01-01T00:00:00Z" });
        var r = await client.PostCryptoAsync("forward", stale, "x"u8.ToArray());
        r.StatusCode.ShouldBe((HttpStatusCode)422);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.Timestamp);
    }

    [Fact] // Estándar §13.2 #5: requestId repetido
    public async Task E_DUPLICATE_request_id()
    {
        var req = ApiHelpers.Request(factory, Ids.Eq03, "HASHSHA", "forward");
        (await client.PostCryptoAsync("forward", req, "x"u8.ToArray())).StatusCode.ShouldBe(HttpStatusCode.OK);
        var r = await client.PostCryptoAsync("forward", req, "x"u8.ToArray());
        r.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.Duplicate);
    }

    [Fact] // Estándar §13.2 #6
    public async Task E_ALGORITHM_NOT_PROVIDED_for_foreign_algorithm()
    {
        var r = await client.PostCryptoAsync("forward", ApiHelpers.Request(factory, Ids.Eq03, "AESGCM", "forward"), "x"u8.ToArray());
        r.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.AlgorithmNotProvided);
    }

    [Fact] // Estándar §13.2 #6: código inexistente
    public async Task E_ALGORITHM_unknown_code()
    {
        var r = await client.PostCryptoAsync("forward", ApiHelpers.Request(factory, Ids.Eq03, "MD5", "forward"), "x"u8.ToArray());
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.Algorithm);
    }

    [Fact] // Estándar §13.2 #7: sobre para otro nodo
    public async Task E_ENV_RECIPIENT()
    {
        var req = ApiHelpers.Request(factory, Ids.Eq03, "HMACSHA256", "forward", new() { ["key"] = ApiHelpers.HmacKey },
            edit: s => s with { TargetCertificate = Ids.Eq05.Certificate });
        var r = await client.PostCryptoAsync("forward", req, "x"u8.ToArray());
        r.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.EnvRecipient);
    }

    [Fact] // Estándar §13.2 #7: sobre ilegible
    public async Task E_ENV_DECRYPT()
    {
        var req = ApiHelpers.Request(factory, Ids.Eq03, "HMACSHA256", "forward", new() { ["key"] = ApiHelpers.HmacKey });
        var bad = Packaging.Client.CryptoRequestBuilder.Sign(Ids.Eq03, req.Request with
        {
            Secrets = req.Request.Secrets! with { TagBase64 = Convert.ToBase64String(new byte[16]) },
        });
        var r = await client.PostCryptoAsync("forward", bad, "x"u8.ToArray());
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.EnvDecrypt);
    }

    [Fact] // Estándar §13.2 #8
    public async Task E_PARAMS_short_hmac_key()
    {
        var req = ApiHelpers.Request(factory, Ids.Eq03, "HMACSHA256", "forward", new() { ["key"] = Convert.ToBase64String(new byte[16]) });
        var r = await client.PostCryptoAsync("forward", req, "x"u8.ToArray());
        r.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.Params);
    }

    [Fact] // Estándar §13.2 #1 + §13.1 sobre el paquete en inverse
    public async Task Inverse_with_tampered_package_returns_E_HASH()
    {
        var entries = Packaging.Tests.ZipTools.Read(ApiHelpers.HashPackage(Ids.Eq05).Zip);
        entries["datos.enc"][0] ^= 1;
        var r = await client.PostCryptoAsync("inverse", ApiHelpers.Request(factory, Ids.Eq03, "HASHSHA", "inverse"),
            package: Packaging.Tests.ZipTools.Write(entries));
        r.StatusCode.ShouldBe((HttpStatusCode)422);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.Hash);
    }

    [Fact] // Estándar §10.1: E-UNSUPPORTED-MEDIA
    public async Task E_UNSUPPORTED_MEDIA_for_json_body()
    {
        var r = await client.PostAsync(new Uri("/api/crypto/forward", UriKind.Relative), new StringContent("{}", Encoding.UTF8, "application/json"));
        r.StatusCode.ShouldBe(HttpStatusCode.UnsupportedMediaType);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.UnsupportedMedia);
    }

    [Fact] // ADR 0006: solicitante no fijado queda pendiente en el directorio
    public async Task Unpinned_requester_is_registered_as_pending()
    {
        await client.PostCryptoAsync("forward", ApiHelpers.Request(factory, Ids.Eq03, "HASHSHA", "forward"), "x"u8.ToArray());
        var dir = factory.Services.GetRequiredService<Application.Services.NodeDirectory>();
        var node = await dir.FindAsync("EQ03");
        node!.TrustState.ShouldBe(Infrastructure.Data.Entities.TrustStates.Pending);
        node.ObservedThumbprintSha256.ShouldBe(Ids.Eq03.Thumbprint);
    }
}
