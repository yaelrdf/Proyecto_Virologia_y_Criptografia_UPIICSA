using System.Net;
using Bunit;
using CentroCiber.Application;
using CentroCiber.Application.Notifications;
using CentroCiber.Application.Providers;
using CentroCiber.Crypto.Algorithms;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Discovery;
using CentroCiber.Infrastructure.Configuration;
using CentroCiber.Infrastructure.Data.Entities;
using CentroCiber.Packaging.Contracts;
using CentroCiber.Web.Components.Shared;
using CentroCiber.Web.Middleware;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace CentroCiber.Web.Tests;

public class AlgorithmFormTests : BunitContext
{
    private static AlgorithmProfile HmacProfile =>
        AlgorithmProfiles.For(new HmacSha256Algorithm(), new HashSet<string> { "HMAC-SHA256" });

    [Fact] // Estándar §10.4: el formulario se construye desde el perfil
    public void Renders_options_and_secrets_from_profile()
    {
        var cut = Render<AlgorithmForm>(p => p.Add(x => x.Profile, HmacProfile).Add(x => x.Operation, "forward"));
        cut.Find("select#opt-macAlgorithm").QuerySelectorAll("option").Select(o => o.TextContent).ShouldBe(["HMAC-SHA256"]);
        cut.Find("input#sec-key").GetAttribute("type").ShouldBe("password");
        cut.Markup.ShouldContain("≥ 32 bytes");
    }

    [Fact] // Plan §1: botón «Generar clave» (32 bytes aleatorios)
    public void Generate_key_fills_32_random_bytes()
    {
        var secrets = new Dictionary<string, string>();
        var cut = Render<AlgorithmForm>(p => p.Add(x => x.Profile, HmacProfile).Add(x => x.SecretValues, secrets));
        cut.Find("button").Click();
        Convert.FromBase64String(secrets["key"]).Length.ShouldBe(32);
        cut.Markup.ShouldContain("Clave generada");
    }

    [Fact] // inverse: sin opciones públicas; secretos requeridos para inverse
    public void Inverse_mode_hides_options()
    {
        var cut = Render<AlgorithmForm>(p => p.Add(x => x.Profile, HmacProfile).Add(x => x.Operation, "inverse"));
        cut.FindAll("select").Count.ShouldBe(0);
        cut.FindAll("input#sec-key").Count.ShouldBe(1);
    }

    [Fact] // Perfil mínimo de la tabla 4.2 para algoritmos sin perfil publicado
    public void Generic_profile_for_foreign_algorithm()
    {
        var profile = AlgorithmProfiles.Generic(AlgorithmCatalog.ByCode("CAESAR")!);
        var cut = Render<AlgorithmForm>(p => p.Add(x => x.Profile, profile));
        cut.FindAll("input#sec-shift").Count.ShouldBe(1);
    }
}

public class InboxAndNodeTableTests : BunitContext
{
    private static InboxRequestEntity Row(string validation, string status = RequestStates.Pending, bool sample = false) => new()
    {
        Id = 7,
        PacketId = Identifiers.NewUuid(),
        SourceNode = "EQ05",
        SourceIp = "192.168.1.25:5005",
        FileName = "EQ05_VIGENERE_20261125_162500_60303AE2.zip",
        AlgorithmCode = "VIGENERE",
        OperationName = "cifrar",
        ValidationResult = validation,
        Status = status,
        IsSample = sample,
    };

    [Fact] // Estándar §15: columnas, «Remitente no confirmado» y botones Aceptar/Rechazar
    public void Inbox_shows_validation_and_actions()
    {
        InboxRequestEntity? accepted = null;
        var cut = Render<InboxTable>(p => p
            .Add(x => x.Items, [Row(ValidationLabels.Unconfirmed)])
            .Add(x => x.OnAccept, r => accepted = r));
        cut.Find("span.badge.warn").TextContent.ShouldBe("Remitente no confirmado");
        cut.Markup.ShouldContain("192.168.1.25:5005");
        cut.Markup.ShouldContain("cifrar");
        cut.Find("button.btn.chico").Click();
        accepted!.Id.ShouldBe(7);
        cut.FindAll("button").Select(b => b.TextContent).ShouldBe(["Aceptar", "Rechazar"]);
    }

    [Fact] // Estado distinto de Pendiente o registro de ejemplo: sin botones
    public void Decided_or_sample_rows_have_no_actions()
    {
        var cut = Render<InboxTable>(p => p.Add(x => x.Items, [Row(ValidationLabels.SignatureOk, RequestStates.Accepted), Row(ValidationLabels.Invalid, sample: true)]));
        cut.FindAll("button").Count.ShouldBe(0);
        cut.Find("span.badge.ok").TextContent.ShouldBe("Firma OK");
        cut.Find("span.badge.error").TextContent.ShouldBe("Inválida");
    }

    [Fact] // Estándar §6.3 #5: la interfaz DEBE alertar del cambio de huella
    public void Node_table_alerts_on_thumbprint_change()
    {
        var node = new NodeEntity
        {
            NodeId = "EQ03", TeamNumber = 3, Ip = "192.168.1.23", HttpPort = 5003, Source = "beacon", Status = "online",
            TrustState = TrustStates.ThumbprintChanged, PinnedThumbprintSha256 = new string('A', 64), ObservedThumbprintSha256 = new string('B', 64),
            Algorithms = "RSA,ECC",
        };
        NodeEntity? confirmed = null;
        var cut = Render<NodeTable>(p => p.Add(x => x.Items, [node]).Add(x => x.OnConfirm, n => confirmed = n));
        cut.Find("[role=alert]").TextContent.ShouldContain("La huella de EQ03 cambió");
        cut.Find("span.badge.error").TextContent.ShouldBe("Huella cambiada");
        cut.FindAll("button").First(b => b.TextContent == "Aceptar nueva huella").Click();
        confirmed!.NodeId.ShouldBe("EQ03");
    }
}

public sealed class StatusAndToastTests : BunitContext
{
    private static readonly NodeIdentity Identity = NodeIdentity.Create(8, TimeProvider.System);

    public StatusAndToastTests()
    {
        var context = new NodeContext(new NodeOptions { AdvertisedIp = "192.168.1.14" }, Identity,
            Path.Combine(Path.GetTempPath(), "cc-bunit"), httpsActive: true, TimeProvider.System);
        Services.AddSingleton(context);
        Services.AddSingleton(new NotificationHub());
        Services.AddSingleton(new BeaconService(new BeaconSettings(false, 5099, [], TimeSpan.FromSeconds(30), null),
            new FakePeer(), NullLogger<BeaconService>.Instance));
    }

    [Fact] // Plan §5: barra de estado con EQ08, IP, puertos 5008/5108 y oyente UDP
    public void Status_bar_shows_node_ip_ports_and_listener()
    {
        var cut = Render<StatusBar>();
        cut.Markup.ShouldContain("EQ08");
        cut.Markup.ShouldContain("192.168.1.14");
        cut.Markup.ShouldContain("5008");
        cut.Markup.ShouldContain("5108");
        cut.Markup.ShouldContain("Oyente UDP inactivo");
    }

    [Fact] // Plan §5: notificaciones en tiempo real
    public void Toasts_show_published_events()
    {
        var hub = Services.GetRequiredService<NotificationHub>();
        var cut = Render<NotificationToasts>();
        hub.Publish(new NodeEvent(NodeEventKind.InboxReceived, "Nueva solicitud de EQ05", DateTimeOffset.UtcNow));
        cut.WaitForAssertion(() => cut.Find(".toast").TextContent.ShouldContain("Nueva solicitud de EQ05"));
        var bar = Render<StatusBar>();
        hub.Publish(new NodeEvent(NodeEventKind.ThumbprintChanged, "¡Alerta!", DateTimeOffset.UtcNow));
        cut.WaitForAssertion(() => cut.FindAll(".toast.alerta-huella").Count.ShouldBe(1));
        bar.WaitForAssertion(() => bar.Markup.ShouldContain("evento(s) nuevos"));
    }

    private sealed class FakePeer : IBeaconPeer
    {
        public string OwnNodeId => "EQ08";

        public Beacon CreateBeacon(IPAddress localAddress, string status) => throw new NotSupportedException();

        public Task OnBeaconAsync(Beacon beacon, IPEndPoint from, CancellationToken ct) => Task.CompletedTask;
    }
}

public class LanOnlyTests
{
    [Theory] // Plan §5: la interfaz solo responde a IP privadas/loopback
    [InlineData("127.0.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.16.0.5", true)]
    [InlineData("172.31.255.1", true)]
    [InlineData("192.168.1.14", true)]
    [InlineData("::ffff:192.168.1.14", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("8.8.8.8", false)]
    [InlineData("2001:4860:4860::8888", false)]
    public void Private_addresses_are_allowed(string ip, bool allowed) =>
        LanOnlyMiddleware.IsAllowed(IPAddress.Parse(ip)).ShouldBe(allowed);

    [Fact] // La API sigue abierta a cualquier IP; la interfaz no
    public async Task Middleware_blocks_ui_but_not_api_for_public_ip()
    {
        var called = 0;
        var mw = new LanOnlyMiddleware(_ =>
        {
            called++;
            return Task.CompletedTask;
        });
        var ui = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        ui.Request.Path = "/consultas";
        ui.Connection.RemoteIpAddress = IPAddress.Parse("8.8.8.8");
        ui.Response.Body = new MemoryStream();
        await mw.InvokeAsync(ui);
        ui.Response.StatusCode.ShouldBe(403);

        var api = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        api.Request.Path = "/api/status";
        api.Connection.RemoteIpAddress = IPAddress.Parse("8.8.8.8");
        await mw.InvokeAsync(api);
        called.ShouldBe(1);
    }
}
