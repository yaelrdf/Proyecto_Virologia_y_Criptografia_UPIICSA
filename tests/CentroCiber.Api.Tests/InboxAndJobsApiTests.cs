using System.Net;
using System.Text.Json;
using CentroCiber.Application.Services;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Infrastructure.Data;
using CentroCiber.Infrastructure.Data.Entities;
using CentroCiber.Packaging.Contracts;
using Microsoft.EntityFrameworkCore;

namespace CentroCiber.Api.Tests;

public class InboxApiTests
{
    [Fact] // Estándar §10.5 y §15
    public async Task Receive_returns_202_and_pending_request_marked_unconfirmed()
    {
        using var f = new NodeFactory();
        using var client = f.CreateClient();
        var pkg = ApiHelpers.HashPackage(Ids.Eq05);
        var r = await client.PostPackageAsync(pkg.Zip);
        r.StatusCode.ShouldBe(HttpStatusCode.Accepted);
        var body = await r.Content.ReadFromJsonAsync<ReceiveResponse>();
        body!.PacketId.ShouldBe(pkg.Manifest.PacketId);
        body.Status.ShouldBe("Pendiente");
        var inbox = f.Services.GetRequiredService<InboxService>();
        var row = (await inbox.ListAsync()).First(x => x.PacketId == pkg.Manifest.PacketId);
        row.ValidationResult.ShouldBe(ValidationLabels.Unconfirmed); // §13.1: no fijado
        row.FileName.ShouldBe(pkg.FileName);

        // Aceptar → Consultas con origen Recibido
        var stored = await inbox.AcceptAsync(row.Id);
        stored.Origin.ShouldBe(PackageOrigins.Received);
        (await f.Services.GetRequiredService<PackageLibrary>().ReadZipAsync(stored)).ShouldBe(pkg.Zip);
    }

    [Fact] // Estándar §13.1 #14 por API
    public async Task E_DUPLICATE_packet()
    {
        using var f = new NodeFactory();
        using var client = f.CreateClient();
        var zip = ApiHelpers.HashPackage(Ids.Eq05).Zip;
        (await client.PostPackageAsync(zip)).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        var r = await client.PostPackageAsync(zip);
        r.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.Duplicate);
    }

    [Fact] // Estándar §13.1 #3 por API: zip con 4 archivos
    public async Task E_ZIP_STRUCTURE_by_api()
    {
        using var f = new NodeFactory();
        using var client = f.CreateClient();
        var e = Packaging.Tests.ZipTools.Read(ApiHelpers.HashPackage(Ids.Eq05).Zip);
        e["extra.bin"] = [1];
        var r = await client.PostPackageAsync(Packaging.Tests.ZipTools.Write(e));
        r.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.ZipStructure);
    }

    [Fact] // Estándar §13.1 #2 por API
    public async Task E_ZIP_INVALID_by_api()
    {
        using var f = new NodeFactory();
        using var client = f.CreateClient();
        (await (await client.PostPackageAsync("nada"u8.ToArray())).ProblemCodeAsync()).ShouldBe(ErrorCodes.ZipInvalid);
    }

    [Fact] // Estándar §13.1 #12 por API + registro "Inválida"
    public async Task E_SIGNATURE_by_api_is_recorded_as_invalid()
    {
        using var f = new NodeFactory();
        using var client = f.CreateClient();
        var pkg = ApiHelpers.HashPackage(Ids.Eq05);
        var zip = Packaging.Tests.ZipTools.EditManifest(pkg.Zip, m => m["operationName"] = "x", null);
        zip = Packaging.Tests.ZipTools.EditManifest(zip, m => m["operation"] = "inverse");
        var r = await client.PostPackageAsync(zip);
        r.StatusCode.ShouldBe((HttpStatusCode)422);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.Signature);
        var row = (await f.Services.GetRequiredService<InboxService>().ListAsync()).First(x => x.PacketId == pkg.Manifest.PacketId);
        row.ValidationResult.ShouldBe(ValidationLabels.Invalid);
        row.Status.ShouldBe(RequestStates.Rejected);
    }

    [Fact] // Estándar §13.1 nota: E-CERT-UNTRUSTED por API
    public async Task E_CERT_UNTRUSTED_by_api()
    {
        using var f = new NodeFactory();
        using var client = f.CreateClient();
        await PinAsync(f, "EQ05", Ids.Eq03.Thumbprint);
        var r = await client.PostPackageAsync(ApiHelpers.HashPackage(Ids.Eq05).Zip);
        r.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.CertUntrusted);
    }

    [Fact] // Estándar §15: remitente fijado → "Firma OK"
    public async Task Pinned_sender_shows_signature_ok()
    {
        using var f = new NodeFactory();
        using var client = f.CreateClient();
        await PinAsync(f, "EQ05", Ids.Eq05.Thumbprint);
        var pkg = ApiHelpers.HashPackage(Ids.Eq05);
        (await client.PostPackageAsync(pkg.Zip)).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        var row = (await f.Services.GetRequiredService<InboxService>().ListAsync()).First(x => x.PacketId == pkg.Manifest.PacketId);
        row.ValidationResult.ShouldBe(ValidationLabels.SignatureOk);
    }

    [Fact] // Estándar §13.1 #1 por API
    public async Task E_SIZE_by_api()
    {
        using var f = new NodeFactory();
        using var client = f.CreateClient();
        var r = await client.PostPackageAsync(new byte[ProtocolConstants.MaxBodyBytes + (2 * 1024 * 1024)]);
        r.StatusCode.ShouldBe(HttpStatusCode.RequestEntityTooLarge);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.Size);
    }

    [Fact] // Estándar §13.3: E-BUSY (también si no acepta paquetes)
    public async Task E_BUSY_when_not_accepting_packages()
    {
        using var f = new NodeFactory();
        using var client = f.CreateClient();
        var settings = f.Services.GetRequiredService<SettingsService>();
        var s = await settings.GetAsync();
        s.AcceptingPackages = false;
        await settings.SaveAsync(s);
        var r = await client.PostPackageAsync(ApiHelpers.HashPackage(Ids.Eq05).Zip);
        r.StatusCode.ShouldBe(HttpStatusCode.ServiceUnavailable);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.Busy);
        (await client.GetFromJsonAsync<StatusResponse>("/api/status"))!.AcceptingPackages.ShouldBeFalse();
    }

    [Fact] // Estándar §13.3: más de N peticiones simultáneas → E-BUSY
    public async Task E_BUSY_concurrency_limit()
    {
        using var f = new NodeFactory(new() { ["Node:MaxConcurrentCryptoRequests"] = "0" });
        using var client = f.CreateClient();
        var r = await client.PostCryptoAsync("forward", ApiHelpers.Request(f, Ids.Eq03, "HASHSHA", "forward"), "x"u8.ToArray());
        r.StatusCode.ShouldBe(HttpStatusCode.ServiceUnavailable);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.Busy);
    }

    [Fact] // Estándar §10.5: falta la parte package
    public async Task E_REQUEST_missing_package_part()
    {
        using var f = new NodeFactory();
        using var client = f.CreateClient();
        var content = new MultipartFormDataContent { { new StringContent("x"), "otro" } };
        var r = await client.PostAsync(new Uri("/api/requests/receive", UriKind.Relative), content);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.Request);
    }

    internal static async Task PinAsync(NodeFactory f, string nodeId, string thumbprint)
    {
        var dbf = f.Services.GetRequiredService<IDbContextFactory<CentroCiberDbContext>>();
        await using var db = await dbf.CreateDbContextAsync();
        db.Nodes.Add(new NodeEntity
        {
            NodeId = nodeId,
            TeamNumber = int.Parse(nodeId[2..], System.Globalization.CultureInfo.InvariantCulture),
            Ip = "127.0.0.1",
            HttpPort = 5000,
            Source = NodeSources.Manual,
            Status = "online",
            TrustState = TrustStates.Pinned,
            PinnedThumbprintSha256 = thumbprint,
        });
        await db.SaveChangesAsync();
    }
}

public class JobsApiTests
{
    [Fact] // Estándar §10.6 #4 y §10.7: 202 + jobId, estado y resultado solo para el solicitante
    public async Task Async_job_lifecycle()
    {
        using var f = new NodeFactory(new() { ["Node:SyncTimeoutSeconds"] = "0" });
        using var client = f.CreateClient();
        var r = await client.PostCryptoAsync("forward", ApiHelpers.Request(f, Ids.Eq03, "HASHSHA", "forward"), "async"u8.ToArray());
        r.StatusCode.ShouldBe(HttpStatusCode.Accepted);
        var job = await r.Content.ReadFromJsonAsync<JobAccepted>();
        job!.StatusUrl.ShouldBe($"/api/jobs/{job.JobId}");
        job.RetryAfterSeconds.ShouldBe(5);

        JobStatusResponse? status = null;
        for (var i = 0; i < 50; i++)
        {
            status = await client.GetFromJsonAsync<JobStatusResponse>(job.StatusUrl);
            if (status!.State == "done")
            {
                break;
            }

            await Task.Delay(100);
        }

        status!.State.ShouldBe("done");
        status.ResultUrl.ShouldBe($"/api/jobs/{job.JobId}/result");

        using var asOther = new HttpRequestMessage(HttpMethod.Get, new Uri(status.ResultUrl!, UriKind.Relative));
        asOther.Headers.Add("X-CC-Node", "EQ05");
        var denied = await client.SendAsync(asOther);
        (await denied.ProblemCodeAsync()).ShouldBe(ErrorCodes.JobNotFound);

        using var asRequester = new HttpRequestMessage(HttpMethod.Get, new Uri(status.ResultUrl!, UriKind.Relative));
        asRequester.Headers.Add("X-CC-Node", "EQ03");
        var ok = await client.SendAsync(asRequester);
        ok.StatusCode.ShouldBe(HttpStatusCode.OK);
        ok.Content.Headers.ContentType!.MediaType.ShouldBe("application/zip");
    }

    [Fact] // Estándar §10.7: trabajo fallido reporta el código
    public async Task Failed_job_reports_error()
    {
        using var f = new NodeFactory(new() { ["Node:SyncTimeoutSeconds"] = "0" });
        using var client = f.CreateClient();
        var req = ApiHelpers.Request(f, Ids.Eq03, "HASHSHA", "forward", options: new() { ["hashAlgorithm"] = "SHA3-256" });
        var job = await (await client.PostCryptoAsync("forward", req, "x"u8.ToArray())).Content.ReadFromJsonAsync<JobAccepted>();
        JobStatusResponse? status = null;
        for (var i = 0; i < 50 && status?.State != "failed"; i++)
        {
            await Task.Delay(100);
            status = await client.GetFromJsonAsync<JobStatusResponse>(job!.StatusUrl);
        }

        status!.State.ShouldBe("failed");
        status.Error!.Code.ShouldBe(ErrorCodes.Params);
    }

    [Fact] // Anexo B: E-JOB-NOT-FOUND
    public async Task Unknown_job_returns_404()
    {
        using var f = new NodeFactory();
        using var client = f.CreateClient();
        var r = await client.GetAsync(new Uri($"/api/jobs/{Identifiers.NewUuid()}", UriKind.Relative));
        r.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await r.ProblemCodeAsync()).ShouldBe(ErrorCodes.JobNotFound);
    }

    [Fact] // Estándar §10.7: retención ≥ 1 h
    public void Job_queue_keeps_results_one_hour()
    {
        var clock = new Microsoft.Extensions.Time.Testing.FakeTimeProvider();
        var queue = new Application.Jobs.JobQueue(clock);
        var job = queue.Track("EQ03", Identifiers.NewUuid(), Task.FromResult((new byte[] { 1 }, "a.zip")));
        clock.Advance(TimeSpan.FromMinutes(59));
        queue.Get(job.JobId).ShouldNotBeNull();
        clock.Advance(TimeSpan.FromMinutes(2));
        queue.Get(job.JobId).ShouldBeNull();
    }
}

public class HttpsAndOpenApiTests
{
    [Fact] // Estándar §5.2: HTTPS con el mismo certificado de identidad (huella fijada)
    public async Task Https_uses_identity_certificate()
    {
        await using var node = await RealNode.StartAsync();
        var expected = node.Services.GetRequiredService<Application.NodeContext>().Identity.Thumbprint;
        string? seen = null;
        using var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
            {
                seen = Crypto.Identity.CertificateTools.Thumbprint(new System.Security.Cryptography.X509Certificates.X509Certificate2(cert!));
                return seen == expected;
            },
        };
        using var client = new HttpClient(handler);
        var status = await client.GetFromJsonAsync<StatusResponse>(new Uri($"https://127.0.0.1:{node.HttpsPort}/api/status"));
        seen.ShouldBe(expected);
        status!.HttpsPort.ShouldBe(node.HttpsPort);

        using var http = new HttpClient();
        (await http.GetFromJsonAsync<StatusResponse>(new Uri(node.HttpBase, "/api/status")))!.HttpPort.ShouldBe(node.HttpPort);
    }

    [Fact] // docs/api/openapi.json debe estar al día con la API
    public async Task Openapi_document_is_up_to_date()
    {
        using var f = new NodeFactory();
        using var client = f.CreateClient();
        var json = await client.GetStringAsync(new Uri("/openapi/v1.json", UriKind.Relative));
        using var doc = JsonDocument.Parse(json);
        var paths = doc.RootElement.GetProperty("paths").EnumerateObject().Select(p => p.Name).ToList();
        paths.ShouldContain("/api/status");
        paths.ShouldContain("/api/crypto/forward");
        paths.ShouldContain("/api/jobs/{jobId}/result");
        var pretty = JsonSerializer.Serialize(doc.RootElement, new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        }) + "\n";
        var target = Path.Combine(Packaging.Tests.RepoPaths.Root, "docs", "api", "openapi.json");
        if (Environment.GetEnvironmentVariable("CC_UPDATE_OPENAPI") == "1")
        {
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            await File.WriteAllTextAsync(target, pretty);
        }

        File.Exists(target).ShouldBeTrue("Genera el documento con: CC_UPDATE_OPENAPI=1 dotnet test --filter Openapi");
        (await File.ReadAllTextAsync(target)).ReplaceLineEndings("\n").ShouldBe(pretty.ReplaceLineEndings("\n"),
            "docs/api/openapi.json está desactualizado. Regenera con: CC_UPDATE_OPENAPI=1 dotnet test --filter Openapi");
    }
}
