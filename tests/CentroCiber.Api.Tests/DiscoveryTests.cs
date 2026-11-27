using System.Net;
using System.Text;
using CentroCiber.Application.Notifications;
using CentroCiber.Application.Services;
using CentroCiber.Discovery;
using CentroCiber.Infrastructure.Data;
using CentroCiber.Infrastructure.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace CentroCiber.Api.Tests;

public class BeaconCodecTests
{
    private static Beacon Sample(string nodeId = "EQ01", int team = 1) => new()
    {
        NodeId = nodeId,
        TeamNumber = team,
        Ip = "192.168.1.21",
        HttpPort = 5001,
        HttpsPort = null,
        Status = "online",
        Algorithms = ["AESGCM", "DES"],
        CertificateThumbprintSha256 = new string('A', 64),
        TimestampUtc = "2026-11-25T15:47:00Z",
    };

    [Fact] // Estándar §6.1: JSON UTF-8 ≤ 1024 bytes con los campos del ejemplo
    public void Beacon_is_small_json_with_standard_fields()
    {
        var bytes = BeaconCodec.Encode(Sample());
        bytes.Length.ShouldBeLessThanOrEqualTo(1024);
        var json = Encoding.UTF8.GetString(bytes);
        json.ShouldContain("\"type\":\"CC-BEACON\"");
        json.ShouldContain("\"protocolVersion\":\"2.0\"");
        json.ShouldContain("\"httpsPort\":null");
        BeaconCodec.Decode(bytes, "EQ08")!.NodeId.ShouldBe("EQ01");
    }

    [Fact] // Estándar §6.1: ignorar propios y los de type/protocolVersion distintos
    public void Own_and_foreign_version_beacons_are_ignored()
    {
        BeaconCodec.Decode(BeaconCodec.Encode(Sample("EQ08", 8)), "EQ08").ShouldBeNull();
        BeaconCodec.Decode(BeaconCodec.Encode(Sample() with { Type = "OTRO" }), "EQ08").ShouldBeNull();
        BeaconCodec.Decode(BeaconCodec.Encode(Sample() with { ProtocolVersion = "1.0" }), "EQ08").ShouldBeNull();
        BeaconCodec.Decode(BeaconCodec.Encode(Sample("EQ02", 1)), "EQ08").ShouldBeNull();
        BeaconCodec.Decode("basura"u8, "EQ08").ShouldBeNull();
        BeaconCodec.Decode(new byte[1025], "EQ08").ShouldBeNull();
    }
}

public class DirectoryAndDiscoveryTests
{
    private static Dictionary<string, string?> Udp(int listen, int target) => new()
    {
        ["Node:Discovery:Enabled"] = "true",
        ["Node:Discovery:ListenPort"] = listen.ToString(System.Globalization.CultureInfo.InvariantCulture),
        ["Node:Discovery:Targets:0"] = $"127.0.0.1:{target}",
        ["Node:Discovery:IntervalSeconds"] = "1",
    };

    private static async Task<NodeEntity?> WaitForAsync(RealNode node, string nodeId, Func<NodeEntity, bool> condition)
    {
        var dir = node.Services.GetRequiredService<NodeDirectory>();
        for (var i = 0; i < 100; i++)
        {
            var n = await dir.FindAsync(nodeId);
            if (n is not null && condition(n))
            {
                return n;
            }

            await Task.Delay(100);
        }

        return await dir.FindAsync(nodeId);
    }

    [Fact] // Estándar §6.1 y §6.3: dos instancias en loopback se descubren por UDP y se verifican
    public async Task Two_nodes_discover_each_other_over_udp_and_tofu()
    {
        var ua = RealNode.FreeUdpPort();
        var ub = RealNode.FreeUdpPort();
        await using var a = await RealNode.StartAsync(8, Udp(ua, ub));
        await using var b = await RealNode.StartAsync(9, Udp(ub, ua));

        var seenByA = await WaitForAsync(a, "EQ09", n => n.CertificatePem is not null);
        seenByA.ShouldNotBeNull();
        seenByA.Source.ShouldBe(NodeSources.Beacon);
        seenByA.Ip.ShouldBe("127.0.0.1");
        seenByA.HttpPort.ShouldBe(b.HttpPort);
        seenByA.TrustState.ShouldBe(TrustStates.Pending); // §6.3 #4: el usuario debe confirmar
        seenByA.ObservedThumbprintSha256.ShouldBe(b.Services.GetRequiredService<Application.NodeContext>().Identity.Thumbprint);
        (await WaitForAsync(b, "EQ08", n => n.CertificatePem is not null))!.TrustState.ShouldBe(TrustStates.Pending);

        var dir = a.Services.GetRequiredService<NodeDirectory>();
        (await dir.ConfirmAsync("EQ09")).TrustState.ShouldBe(TrustStates.Pinned);
        (await dir.GetPinnedThumbprintAsync("EQ09", default)).ShouldBe(seenByA.ObservedThumbprintSha256);
        a.Services.GetRequiredService<BeaconService>().Listening.ShouldBeTrue();
    }

    [Fact] // Estándar §6.3 #5: huella distinta a la fijada → alerta y no usar
    public async Task Thumbprint_change_raises_alert()
    {
        await using var a = await RealNode.StartAsync(8);
        await using var b = await RealNode.StartAsync(9);
        var dir = a.Services.GetRequiredService<NodeDirectory>();
        await dir.AddManualAsync("127.0.0.1", b.HttpPort);
        await dir.ConfirmAsync("EQ09");

        // Simula que EQ09 regeneró su certificado: la huella fijada ya no coincide con la observada.
        var dbf = a.Services.GetRequiredService<IDbContextFactory<CentroCiberDbContext>>();
        await using (var db = await dbf.CreateDbContextAsync())
        {
            var n = await db.Nodes.FirstAsync(x => x.NodeId == "EQ09");
            n.PinnedThumbprintSha256 = new string('B', 64);
            await db.SaveChangesAsync();
        }

        var hub = a.Services.GetRequiredService<NotificationHub>();
        NodeEvent? alert = null;
        hub.Published += e =>
        {
            if (e.Kind == NodeEventKind.ThumbprintChanged)
            {
                alert = e;
            }
        };
        var verified = await dir.VerifyAsync("EQ09");
        verified!.TrustState.ShouldBe(TrustStates.ThumbprintChanged);
        alert.ShouldNotBeNull();
        alert.Message.ShouldContain("cambió");

        // El usuario la acepta de nuevo
        (await dir.ConfirmAsync("EQ09")).TrustState.ShouldBe(TrustStates.Pinned);
    }

    [Fact] // Estándar §6.3 #1: alta manual
    public async Task Manual_add_verifies_status_and_certificate()
    {
        await using var a = await RealNode.StartAsync(8);
        await using var b = await RealNode.StartAsync(9);
        var n = await a.Services.GetRequiredService<NodeDirectory>().AddManualAsync("127.0.0.1", b.HttpPort);
        n.NodeId.ShouldBe("EQ09");
        n.Source.ShouldBe(NodeSources.Manual);
        n.CertificatePem.ShouldStartWith("-----BEGIN CERTIFICATE-----");
        n.ProfileJson.ShouldNotBeNull();
        await Should.ThrowAsync<InvalidOperationException>(() =>
            a.Services.GetRequiredService<NodeDirectory>().AddManualAsync("127.0.0.1", a.HttpPort));
    }

    [Fact] // Estándar §6.2: escaneo HTTP de respaldo
    public async Task Scan_finds_node_on_port_range()
    {
        await using var b = await RealNode.StartAsync(9);
        await using var a = await RealNode.StartAsync(8, new()
        {
            ["Node:Discovery:ScanPortFrom"] = (b.HttpPort - 2).ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Node:Discovery:ScanPortTo"] = (b.HttpPort + 2).ToString(System.Globalization.CultureInfo.InvariantCulture),
        });
        var hits = await a.Services.GetRequiredService<NodeDirectory>().ScanAsync(
            a.Services.GetRequiredService<SubnetScanner>(), [IPAddress.Loopback]);
        hits.Select(h => h.NodeId).ShouldContain("EQ09");
        (await a.Services.GetRequiredService<NodeDirectory>().FindAsync("EQ09"))!.Source.ShouldBe(NodeSources.Scan);
    }

    [Fact] // Estándar §6.2: un ciclo automático no más de una vez cada 5 min
    public void Automatic_scan_is_throttled()
    {
        using var http = new HttpClient();
        var scanner = new SubnetScanner(http);
        var now = DateTimeOffset.UtcNow;
        scanner.TryBeginAutomatic(now).ShouldBeTrue();
        scanner.TryBeginAutomatic(now.AddMinutes(4)).ShouldBeFalse();
        scanner.TryBeginAutomatic(now.AddMinutes(5)).ShouldBeTrue();
        SubnetScanner.Slash24(IPAddress.Parse("192.168.1.14")).Count().ShouldBe(254);
    }

    [Fact] // Estándar §6.1: offline tras 90 s sin señal
    public async Task Silent_node_goes_offline_after_90_seconds()
    {
        await using var a = await RealNode.StartAsync(8);
        var dbf = a.Services.GetRequiredService<IDbContextFactory<CentroCiberDbContext>>();
        await using (var db = await dbf.CreateDbContextAsync())
        {
            db.Nodes.Add(new NodeEntity { NodeId = "EQ01", TeamNumber = 1, Ip = "10.255.0.1", HttpPort = 5001, Source = "beacon", Status = "online", TrustState = TrustStates.Pending, LastSeenUtc = DateTime.UtcNow.AddSeconds(-91) });
            db.Nodes.Add(new NodeEntity { NodeId = "EQ02", TeamNumber = 2, Ip = "10.255.0.2", HttpPort = 5002, Source = "beacon", Status = "online", TrustState = TrustStates.Pending, LastSeenUtc = DateTime.UtcNow.AddSeconds(-60) });
            await db.SaveChangesAsync();
        }

        var dir = a.Services.GetRequiredService<NodeDirectory>();
        (await dir.MarkStaleOfflineAsync()).ShouldBe(1);
        (await dir.FindAsync("EQ01"))!.Status.ShouldBe("offline");
        (await dir.FindAsync("EQ02"))!.Status.ShouldBe("online");
    }
}
