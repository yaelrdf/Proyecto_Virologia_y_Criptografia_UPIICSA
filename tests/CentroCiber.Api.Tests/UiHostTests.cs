using System.Net;

namespace CentroCiber.Api.Tests;

public class UiHostTests
{
    [Theory] // Plan §5 + panel de pruebas: las pantallas se sirven en español
    [InlineData("/", "Operar (ida)")]
    [InlineData("/operar/vuelta", "Operar (vuelta)")]
    [InlineData("/solicitudes", "Solicitudes")]
    [InlineData("/consultas", "Consultas")]
    [InlineData("/nodos", "Nodos")]
    [InlineData("/ajustes", "Ajustes")]
    [InlineData("/bandeja", "Bandeja")]
    [InlineData("/enviar", "Enviar a otro equipo")]
    public async Task Pages_render(string path, string title)
    {
        using var f = new NodeFactory(new() { ["Node:EnableUi"] = "true" });
        using var client = f.CreateClient();
        var r = await client.GetAsync(new Uri(path, UriKind.Relative));
        r.StatusCode.ShouldBe(HttpStatusCode.OK);
        var html = await r.Content.ReadAsStringAsync();
        html.ShouldContain("<html lang=\"es\">");
        html.ShouldContain(title);
        html.ShouldContain("Atalaya");
    }

    [Fact]
    public async Task Missing_download_returns_404()
    {
        using var f = new NodeFactory(new() { ["Node:EnableUi"] = "true" });
        using var client = f.CreateClient();
        (await client.GetAsync(new Uri("/descargas/paquete/9999", UriKind.Relative))).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact] // Panel de pruebas: contenido de una solicitud en línea; HTML ajeno se sirve como texto plano con nosniff
    public async Task Inline_content_is_safe()
    {
        using var f = new NodeFactory(new() { ["Node:EnableUi"] = "true" });
        using var client = f.CreateClient();
        var pkg = ApiHelpers.HashPackage(Ids.Eq05, "<script>alert('x')</script>");
        (await client.PostPackageAsync(pkg.Zip)).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        var row = (await f.Services.GetRequiredService<Application.Services.InboxService>().ListAsync()).Single(r => r.PacketId == pkg.Manifest.PacketId);

        var r = await client.GetAsync(new Uri($"/descargas/datos/solicitud/{row.Id}?inline=true", UriKind.Relative));
        r.StatusCode.ShouldBe(HttpStatusCode.OK);
        r.Content.Headers.ContentType!.MediaType.ShouldBe("text/plain");
        r.Headers.GetValues("X-Content-Type-Options").Single().ShouldBe("nosniff");
        (await r.Content.ReadAsStringAsync()).ShouldBe("<script>alert('x')</script>");
        (await client.GetAsync(new Uri($"/descargas/solicitud/{row.Id}", UriKind.Relative))).Content.Headers.ContentType!.MediaType.ShouldBe("application/zip");
    }
}
