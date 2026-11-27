using System.Net;
using CentroCiber.Application.Services;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Infrastructure.Data.Entities;
using CentroCiber.Packaging.Client;

namespace CentroCiber.Api.Tests;

/// <summary>ADR 0014 y panel de pruebas: tolerancia, diagnóstico y aceptación automática.</summary>
public class TolerancePanelTests
{
    /// <summary>Paquete como el de EQ01 en la prueba real: sin requestId, parts ni keyRef, re-firmado.</summary>
    private static byte[] PackageWithoutNullableFields() =>
        Packaging.Tests.ZipTools.EditManifest(ApiHelpers.HashPackage(Ids.Eq05).Zip, m =>
        {
            m.Remove("requestId");
            m.Remove("parts");
            m.Remove("keyRef");
            m.Remove("verification");
            m.Remove("resultEnvelope");
        }, Ids.Eq05);

    [Fact] // ADR 0014: el caso de la captura (E-MANIFEST: Faltan campos requestId, parts) ahora se acepta
    public async Task Inbox_accepts_manifest_without_nullable_fields()
    {
        using var f = new NodeFactory();
        using var client = f.CreateClient();
        var r = await client.PostPackageAsync(PackageWithoutNullableFields());
        r.StatusCode.ShouldBe(HttpStatusCode.Accepted);
    }

    [Fact] // ADR 0014: inverse también acepta el paquete tolerante
    public async Task Inverse_accepts_manifest_without_nullable_fields()
    {
        using var f = new NodeFactory();
        using var client = f.CreateClient();
        var r = await client.PostCryptoAsync("inverse", ApiHelpers.Request(f, Ids.Eq03, "HASHSHA", "inverse"),
            package: PackageWithoutNullableFields());
        r.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact] // §10.6: options, keyId y secrets pueden omitirse en el objeto request
    public async Task Request_without_optional_members_is_accepted()
    {
        using var f = new NodeFactory();
        using var client = f.CreateClient();
        var bytes = System.Text.Encoding.UTF8.GetBytes(
            $$"""{"version":"2.0","requestId":"{{Identifiers.NewUuid()}}","requesterNode":"EQ03","targetNode":"EQ08","timestampUtc":"{{Identifiers.FormatTimestamp(DateTimeOffset.UtcNow)}}","algorithmCode":"HASHSHA","operation":"forward","payloadMode":"text","originalFileName":"m.txt"}""");
        var req = CryptoRequestBuilder.Sign(Ids.Eq03, CryptoRequestHandler.ParseRequest(bytes, "forward")) with
        {
            RequestBytes = bytes,
            SignatureBase64 = Crypto.Signing.RsaPss.SignBase64(Ids.Eq03.PrivateKey, bytes),
        };
        var r = await client.PostCryptoAsync("forward", req, "x"u8.ToArray());
        r.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact] // Diagnóstico: todo rechazo de la API queda en la bitácora con código, IP, nodo y detalle
    public async Task Rejections_are_recorded_for_diagnostics()
    {
        using var f = new NodeFactory();
        using var client = f.CreateClient();
        var content = new MultipartFormDataContent();
        var file = new ByteArrayContent("no soy zip"u8.ToArray());
        content.Add(file, "package", "x.zip");
        using var msg = new HttpRequestMessage(HttpMethod.Post, new Uri("/api/requests/receive", UriKind.Relative)) { Content = content };
        msg.Headers.Add("X-CC-Node", "EQ01");
        (await client.SendAsync(msg)).StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        var log = await f.Services.GetRequiredService<AuditService>().RecentRejectionsAsync(10);
        var entry = log.First();
        entry.Event.ShouldBe(AuditService.EventApiRejected);
        entry.Code.ShouldBe(ErrorCodes.ZipInvalid);
        entry.NodeId.ShouldBe("EQ01");
        entry.Detail!.ShouldContain("POST /api/requests/receive");
        entry.Detail!.ShouldContain("zip");
    }

    [Fact] // Panel de pruebas: aceptación automática de paquetes válidos
    public async Task Auto_accept_moves_valid_packages_to_consultas()
    {
        using var f = new NodeFactory();
        using var client = f.CreateClient();
        var settings = f.Services.GetRequiredService<SettingsService>();
        var s = await settings.GetAsync();
        s.AutoAcceptInbox = true;
        await settings.SaveAsync(s);

        var pkg = ApiHelpers.HashPackage(Ids.Eq05);
        var r = await client.PostPackageAsync(pkg.Zip);
        r.StatusCode.ShouldBe(HttpStatusCode.Accepted);
        var row = (await f.Services.GetRequiredService<InboxService>().ListAsync()).Single(x => x.PacketId == pkg.Manifest.PacketId);
        row.Status.ShouldBe(RequestStates.Accepted);
        row.PackageId.ShouldNotBeNull();
        (await f.Services.GetRequiredService<PackageLibrary>().GetAsync(row.PackageId!.Value))!.Origin.ShouldBe(PackageOrigins.Received);
    }
}
