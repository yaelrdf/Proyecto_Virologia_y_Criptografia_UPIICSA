using System.Text;
using CentroCiber.Application.Providers;
using CentroCiber.Application.Services;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Infrastructure.Data.Entities;
using CentroCiber.MockNode;

namespace CentroCiber.Api.Tests;

public class DelegationTests
{
    internal static readonly Dictionary<string, string> AesKey = new() { ["key"] = Convert.ToBase64String(Enumerable.Range(0, 32).Select(i => (byte)(i * 7)).ToArray()) };

    internal static async Task TrustAsync(RealNode node, int port)
    {
        var dir = node.Services.GetRequiredService<NodeDirectory>();
        var n = await dir.AddManualAsync("127.0.0.1", port);
        await dir.ConfirmAsync(n.NodeId);
    }

    internal static ForwardRequest AesForward(string text) => new()
    {
        AlgorithmCode = "AESGCM",
        Payload = Encoding.UTF8.GetBytes(text),
        PayloadMode = "text",
        OriginalFileName = "mensaje.txt",
        Options = new Dictionary<string, string> { ["keySizeBits"] = "256" },
        Secrets = AesKey,
    };

    [Theory] // Estándar §11.2 y §11.4: forward + inverse delegados de AESGCM contra el nodo simulado EQ01
    [InlineData(false)]
    [InlineData(true)] // §10.7: el dueño responde 202 y EQ08 consulta el jobId
    public async Task Delegated_AESGCM_round_trip_with_mock_EQ01(bool asyncMode)
    {
        await using var mock = await MockNodeHost.StartAsync(new MockNodeOptions { AlwaysAsync = asyncMode });
        await using var eq08 = await RealNode.StartAsync(8);
        await TrustAsync(eq08, mock.Port);
        var ops = eq08.Services.GetRequiredService<OperationsService>();

        (await ops.AvailabilityAsync(AlgorithmCatalog.ByCode("AESGCM")!)).Available.ShouldBeTrue();
        var fwd = await ops.ForwardAsync(AesForward("secreto para EQ01"));
        fwd.Result.IsPending.ShouldBeFalse();
        fwd.Stored!.Origin.ShouldBe(PackageOrigins.Generated);
        var m = fwd.Result.Manifest!;
        m.SourceNode.ShouldBe("EQ01");
        m.ProducerNode.ShouldBe("EQ01");
        m.AlgorithmCode.ShouldBe("AESGCM");
        m.PublicParameters.Keys.Order().ShouldBe(["keySizeBits", "nonceBase64", "tagBase64"]);
        mock.ForwardCalls.ShouldBe(1);

        var inv = await ops.InverseAsync(new InverseRequest { AlgorithmCode = "AESGCM", PackageZip = fwd.Result.Zip!, Secrets = AesKey });
        inv.Result.Original.ShouldBe(Encoding.UTF8.GetBytes("secreto para EQ01"));
        inv.Stored!.Origin.ShouldBe(PackageOrigins.Result);
        inv.Result.Manifest!.ResultEnvelope!.RecipientNode.ShouldBe("EQ08");
        mock.InverseCalls.ShouldBe(1);
    }

    [Theory] // ADR 0016/0017: variantes de EQ01 observadas en RelayCryptoNode (EQ06)
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, true, true)]
    [InlineData(true, true, true)]
    public async Task Delegation_tolerates_owner_variants(bool omitNulls, bool envelopeInData, bool appendTag)
    {
        await using var mock = await MockNodeHost.StartAsync(new MockNodeOptions
        {
            OmitNullFields = omitNulls,
            EnvelopeInData = envelopeInData,
            AppendTag = appendTag,
        });
        await using var eq08 = await RealNode.StartAsync(8);
        await TrustAsync(eq08, mock.Port);
        var ops = eq08.Services.GetRequiredService<OperationsService>();
        var fwd = await ops.ForwardAsync(AesForward("variante EQ01"));
        var inv = await ops.InverseAsync(new InverseRequest { AlgorithmCode = "AESGCM", PackageZip = fwd.Result.Zip!, Secrets = AesKey });
        inv.Result.Original.ShouldBe(Encoding.UTF8.GetBytes("variante EQ01"));

        // Consultas también abre el resultado guardado (descarga del original).
        var library = eq08.Services.GetRequiredService<PackageLibrary>();
        (await library.OpenResultAsync(await library.ReadZipAsync(inv.Stored!))).ShouldBe(Encoding.UTF8.GetBytes("variante EQ01"));
    }

    [Fact] // Estándar §14: errores del dueño llegan como problem+json con su código
    public async Task Owner_problem_is_propagated()
    {
        await using var mock = await MockNodeHost.StartAsync();
        await using var eq08 = await RealNode.StartAsync(8);
        await TrustAsync(eq08, mock.Port);
        var ops = eq08.Services.GetRequiredService<OperationsService>();
        var ex = await Should.ThrowAsync<ProtocolException>(() => ops.ForwardAsync(AesForward("x") with
        {
            Secrets = new Dictionary<string, string> { ["key"] = Convert.ToBase64String(new byte[5]) },
        }));
        ex.Code.ShouldBe(ErrorCodes.Params);
        ex.Message.ShouldContain("EQ01");
    }

    [Fact] // Estándar §11.6 y §6.3: dueño ausente o sin confirmar → "no disponible" con motivo
    public async Task Unavailable_owner_reports_reason()
    {
        await using var mock = await MockNodeHost.StartAsync();
        await using var eq08 = await RealNode.StartAsync(8);
        var ops = eq08.Services.GetRequiredService<OperationsService>();
        var aes = AlgorithmCatalog.ByCode("AESGCM")!;
        var a = await ops.AvailabilityAsync(aes);
        a.Available.ShouldBeFalse();
        a.Reason.ShouldContain("no está en el directorio");

        await eq08.Services.GetRequiredService<NodeDirectory>().AddManualAsync("127.0.0.1", mock.Port);
        a = await ops.AvailabilityAsync(aes);
        a.Available.ShouldBeFalse();
        a.Reason.ShouldContain("Confirma la huella");
        await Should.ThrowAsync<ProviderUnavailableException>(() => ops.ForwardAsync(AesForward("x")));

        var reserved = await ops.AvailabilityAsync(AlgorithmCatalog.ByCode("DIGITALSIG")!);
        reserved.Available.ShouldBeFalse();
        reserved.Reason.ShouldContain("Sin proveedor");
        (await ops.AvailabilityAsync(AlgorithmCatalog.ByCode("HASHSHA")!)).IsLocal.ShouldBeTrue();
    }

    [Fact] // Estándar §4.4: para reservados gana el teamNumber menor que lo anuncie
    public async Task Reserved_algorithm_prefers_lowest_team()
    {
        await using var eq08 = await RealNode.StartAsync(8);
        var dbf = eq08.Services.GetRequiredService<Microsoft.EntityFrameworkCore.IDbContextFactory<Infrastructure.Data.CentroCiberDbContext>>();
        await using (var db = await dbf.CreateDbContextAsync())
        {
            foreach (var (id, team) in new[] { ("EQ07", 7), ("EQ03", 3) })
            {
                db.Nodes.Add(new NodeEntity
                {
                    NodeId = id,
                    TeamNumber = team,
                    Ip = "127.0.0.1",
                    HttpPort = 5000 + team,
                    Source = "beacon",
                    Status = "online",
                    TrustState = TrustStates.Pinned,
                    PinnedThumbprintSha256 = new string('A', 64),
                    CertificatePem = "x",
                    Algorithms = "DIGITALSIG",
                });
            }

            await db.SaveChangesAsync();
        }

        var a = await eq08.Services.GetRequiredService<OperationsService>().AvailabilityAsync(AlgorithmCatalog.ByCode("DIGITALSIG")!);
        a.ProviderNode.ShouldBe("EQ03");
        a.Available.ShouldBeTrue();
    }

    [Fact] // Estándar §9.6, §11.3 y §12: reenviar un paquete ajeno a la bandeja de un tercero conserva producerNode
    public async Task Forward_foreign_package_to_third_party_inbox()
    {
        await using var mock = await MockNodeHost.StartAsync();
        await using var eq08 = await RealNode.StartAsync(8);
        await using var eq09 = await RealNode.StartAsync(9);
        await TrustAsync(eq08, mock.Port);
        await TrustAsync(eq08, eq09.HttpPort);
        var ops = eq08.Services.GetRequiredService<OperationsService>();
        var fwd = await ops.ForwardAsync(AesForward("para el tercero"));

        var receipt = await ops.SendToInboxAsync("EQ09", fwd.Result.Zip!);
        receipt.Status.ShouldBe("Pendiente");
        var inbox = await eq09.Services.GetRequiredService<InboxService>().ListAsync();
        var row = inbox.Single(r => r.PacketId == receipt.PacketId);
        row.SourceNode.ShouldBe("EQ08");
        row.AlgorithmCode.ShouldBe("AESGCM");
        row.ManifestJson!.ShouldContain("\"producerNode\": \"EQ01\"");
        // ADR 0015: AESGCM usa AAD = packetId; al reenviar se conserva para que EQ01 pueda descifrar.
        receipt.PacketId.ShouldBe(fwd.Result.Manifest!.PacketId);
    }
}

public class EndToEndTests
{
    [Theory] // Definición de terminado: forward → bandeja → aceptar → inverse entre dos nodos locales
    [InlineData("HASHSHA")]
    [InlineData("HMACSHA256")]
    public async Task Two_nodes_exchange_package_end_to_end(string algorithm)
    {
        await using var eq08 = await RealNode.StartAsync(8);
        await using var eq09 = await RealNode.StartAsync(9);

        // Confianza mutua (TOFU): cada usuario confirma la huella del otro.
        var dir08 = eq08.Services.GetRequiredService<NodeDirectory>();
        var dir09 = eq09.Services.GetRequiredService<NodeDirectory>();
        await dir08.ConfirmAsync((await dir08.AddManualAsync("127.0.0.1", eq09.HttpPort)).NodeId);
        await dir09.ConfirmAsync((await dir09.AddManualAsync("127.0.0.1", eq08.HttpPort)).NodeId);

        var key = Convert.ToBase64String(Enumerable.Repeat((byte)0x42, 32).ToArray());
        var secrets = algorithm == "HMACSHA256" ? new Dictionary<string, string> { ["key"] = key } : new Dictionary<string, string>();
        var original = Encoding.UTF8.GetBytes($"Documento de prueba {algorithm} — EQ08 → EQ09");

        // 1. EQ08 ejecuta forward localmente (algoritmo propio).
        var ops08 = eq08.Services.GetRequiredService<OperationsService>();
        var fwd = await ops08.ForwardAsync(new ForwardRequest
        {
            AlgorithmCode = algorithm,
            Payload = original,
            PayloadMode = "text",
            OriginalFileName = "mensaje.txt",
            Secrets = secrets,
        });
        fwd.Result.ProviderNode.ShouldBe("EQ08");

        // 2. EQ08 lo envía a la bandeja de EQ09.
        var receipt = await ops08.SendToInboxAsync("EQ09", fwd.Result.Zip!);

        // 3. EQ09 lo ve como "Firma OK" (EQ08 está fijado) y lo acepta → Consultas (Recibido).
        var inbox = eq09.Services.GetRequiredService<InboxService>();
        var row = (await inbox.ListAsync()).Single(r => r.PacketId == receipt.PacketId);
        row.ValidationResult.ShouldBe(ValidationLabels.SignatureOk);
        var accepted = await inbox.AcceptAsync(row.Id);
        accepted.Origin.ShouldBe(PackageOrigins.Received);

        // 4. EQ09 ejecuta inverse: no es su algoritmo, lo delega a EQ08 (dueño).
        var zip = await eq09.Services.GetRequiredService<PackageLibrary>().ReadZipAsync(accepted);
        var inv = await eq09.Services.GetRequiredService<OperationsService>().InverseAsync(new InverseRequest
        {
            AlgorithmCode = algorithm,
            PackageZip = zip,
            Secrets = secrets,
        });
        inv.Result.ProviderNode.ShouldBe("EQ08");
        inv.Result.Manifest!.Verification!.Valid.ShouldBeTrue();
        inv.Result.Original.ShouldBe(original);
        inv.Stored!.Origin.ShouldBe(PackageOrigins.Result);
    }

    [Fact] // ADR 0015: caso real del panel de pruebas — EQ08 reenvía AESGCM de EQ01 a EQ09 y EQ09 lo descifra con EQ01
    public async Task Forwarded_AESGCM_package_can_be_decrypted_by_third_party()
    {
        await using var mock = await MockNodeHost.StartAsync();
        await using var eq08 = await RealNode.StartAsync(8);
        await using var eq09 = await RealNode.StartAsync(9);
        await DelegationTests.TrustAsync(eq08, mock.Port);
        await DelegationTests.TrustAsync(eq08, eq09.HttpPort);
        await DelegationTests.TrustAsync(eq09, mock.Port);
        var fwd = await eq08.Services.GetRequiredService<OperationsService>().ForwardAsync(DelegationTests.AesForward("Hola EQ09 vía EQ01"));
        var receipt = await eq08.Services.GetRequiredService<OperationsService>().SendToInboxAsync("EQ09", fwd.Result.Zip!);

        var inbox = eq09.Services.GetRequiredService<InboxService>();
        var row = (await inbox.ListAsync()).Single(r => r.PacketId == receipt.PacketId);
        var zip = await inbox.ReadZipAsync(row);
        var inv = await eq09.Services.GetRequiredService<OperationsService>().InverseAsync(new InverseRequest
        {
            AlgorithmCode = "AESGCM",
            PackageZip = zip!,
            Secrets = DelegationTests.AesKey,
        });
        inv.Result.Original.ShouldBe(Encoding.UTF8.GetBytes("Hola EQ09 vía EQ01"));
    }
}
