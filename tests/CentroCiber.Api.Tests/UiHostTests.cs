using System.Net;

namespace CentroCiber.Api.Tests;

public class UiHostTests
{
    [Theory] // Plan §5: las 6 pantallas se sirven en español
    [InlineData("/", "Operar (ida)")]
    [InlineData("/operar/vuelta", "Operar (vuelta)")]
    [InlineData("/solicitudes", "Solicitudes")]
    [InlineData("/consultas", "Consultas")]
    [InlineData("/nodos", "Nodos")]
    [InlineData("/ajustes", "Ajustes")]
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
}
