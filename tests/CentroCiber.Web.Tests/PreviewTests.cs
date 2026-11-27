using Bunit;
using CentroCiber.Web.Api;
using CentroCiber.Web.Components.Shared;

namespace CentroCiber.Web.Tests;

public class PreviewTests : BunitContext
{
    private static readonly byte[] Png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0x0D];

    [Fact] // Panel de pruebas: texto → <pre>
    public void Text_is_shown_in_pre()
    {
        var cut = Render<PackagePreview>(p => p
            .Add(x => x.Data, "Hola EQ08 — ñ"u8.ToArray())
            .Add(x => x.PayloadMode, "text")
            .Add(x => x.FileName, "mensaje.txt"));
        cut.Find("pre.preview-text").TextContent.ShouldBe("Hola EQ08 — ñ");
    }

    [Fact] // Panel de pruebas: imagen (por bytes, aunque el contentType sea genérico) → <img> con URL inline
    public void Image_is_shown_with_inline_url()
    {
        var cut = Render<PackagePreview>(p => p
            .Add(x => x.Data, Png)
            .Add(x => x.ContentType, "application/octet-stream")
            .Add(x => x.FileName, "foto.bin")
            .Add(x => x.ImageUrl, "descargas/datos/solicitud/3?inline=true"));
        cut.Find("img.preview-img").GetAttribute("src").ShouldBe("descargas/datos/solicitud/3?inline=true");
    }

    [Fact] // Binario: no se muestra, solo descarga
    public void Binary_is_download_only()
    {
        var cut = Render<PackagePreview>(p => p
            .Add(x => x.Data, new byte[] { 0, 1, 2, 3, 0, 0, 0, 7 })
            .Add(x => x.FileName, "x.bin")
            .Add(x => x.DownloadUrl, "descargas/x"));
        cut.FindAll("img").Count.ShouldBe(0);
        cut.FindAll("pre").Count.ShouldBe(0);
        cut.Find("a").GetAttribute("href").ShouldBe("descargas/x");
    }

    [Theory] // Seguridad: HTML y SVG nunca se tratan como imagen; JPEG/GIF/BMP sí
    [InlineData(new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 }, "image/jpeg")]
    [InlineData(new byte[] { (byte)'G', (byte)'I', (byte)'F', (byte)'8', (byte)'9', (byte)'a' }, "image/gif")]
    [InlineData(new byte[] { (byte)'B', (byte)'M', 0, 0 }, "image/bmp")]
    public void Raster_images_are_detected(byte[] data, string mime) =>
        PreviewKind.Detect(data, null, null, null).ShouldBe((PreviewType.Image, mime));

    [Fact]
    public void Html_and_svg_are_plain_text_at_most()
    {
        PreviewKind.Detect("<svg onload=alert(1)>"u8, "image/svg+xml", "image", "x.svg").Type.ShouldBe(PreviewType.Text);
        PreviewKind.Detect("<script>alert(1)</script>"u8, "text/html", "file", "x.html").Mime.ShouldBe("text/plain; charset=utf-8");
    }
}
