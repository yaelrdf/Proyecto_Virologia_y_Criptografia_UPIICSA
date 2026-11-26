using System.Net;
using System.Text.Json;
using CentroCiber.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace CentroCiber.Api.Tests;

public class StatusApiTests
{
    [Fact] // Estándar §10.3
    public async Task Status_reports_EQ08_on_port_5008()
    {
        using var factory = new NodeFactory();
        using var client = factory.CreateClient();
        var response = await client.GetAsync(new Uri("/api/status", UriKind.Relative));
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        doc.RootElement.GetProperty("nodeId").GetString().ShouldBe("EQ08");
        doc.RootElement.GetProperty("teamNumber").GetInt32().ShouldBe(8);
        doc.RootElement.GetProperty("httpPort").GetInt32().ShouldBe(5008);
        doc.RootElement.GetProperty("protocolVersion").GetString().ShouldBe("2.0");
        Directory.Exists(factory.DataPath).ShouldBeTrue();
    }

    [Fact] // Requerimiento del curso: BD con ≥ 30 registros
    public async Task Database_is_seeded_with_at_least_30_records()
    {
        using var factory = new NodeFactory();
        _ = factory.CreateClient();
        var dbf = factory.Services.GetRequiredService<IDbContextFactory<CentroCiberDbContext>>();
        await using var db = await dbf.CreateDbContextAsync();
        var total = await db.Algorithms.CountAsync() + await db.Teams.CountAsync() + await db.Nodes.CountAsync()
            + await db.Packages.CountAsync() + await db.Requests.CountAsync() + await db.Settings.CountAsync();
        total.ShouldBe(SeedData.ExpectedRecordCount);
        total.ShouldBeGreaterThanOrEqualTo(30);
    }

    [Fact] // Configuración por variables CC_ (prefijo eliminado)
    public async Task Team_number_can_be_overridden_by_configuration()
    {
        using var factory = new NodeFactory(new() { ["Node:TeamNumber"] = "9" });
        using var client = factory.CreateClient();
        var json = await client.GetStringAsync(new Uri("/api/status", UriKind.Relative));
        json.ShouldContain("\"nodeId\":\"EQ09\"");
        json.ShouldContain("\"httpPort\":5009");
    }
}
