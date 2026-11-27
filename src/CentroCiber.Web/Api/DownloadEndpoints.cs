using CentroCiber.Application.Services;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Packaging;

namespace CentroCiber.Web.Api;

/// <summary>Descargas de la interfaz (solo LAN): zips, contenido de paquetes y original de resultados.</summary>
public static class DownloadEndpoints
{
    public static void MapDownloads(this WebApplication app)
    {
        app.MapGet("/descargas/paquete/{id:int}", async (int id, PackageLibrary library, CancellationToken ct) =>
        {
            var p = await library.GetAsync(id, ct);
            return p?.StoragePath is null
                ? Results.NotFound("Paquete no encontrado.")
                : Results.File(await library.ReadZipAsync(p, ct), ProtocolConstants.ZipContentType, p.FileName);
        }).ExcludeFromDescription();

        app.MapGet("/descargas/solicitud/{id:int}", async (int id, InboxService inbox, CancellationToken ct) =>
        {
            var r = await inbox.GetAsync(id, ct);
            var zip = r is null ? null : await inbox.ReadZipAsync(r, ct);
            return zip is null ? Results.NotFound("Solicitud sin paquete.") : Results.File(zip, ProtocolConstants.ZipContentType, r!.FileName);
        }).ExcludeFromDescription();

        // datos.enc de un paquete de Consultas (legible en HASHSHA/HMACSHA256/DIGITALSIG, §4.3).
        app.MapGet("/descargas/datos/paquete/{id:int}", async (int id, bool? inline, PackageLibrary library, HttpContext http, CancellationToken ct) =>
        {
            var p = await library.GetAsync(id, ct);
            if (p?.StoragePath is null)
            {
                return Results.NotFound("Paquete no encontrado.");
            }

            var v = await library.ValidateForStorageAsync(await library.ReadZipAsync(p, ct), ct);
            return Content(http, v.Data, v.Manifest, inline == true);
        }).ExcludeFromDescription();

        // datos.enc de una solicitud de la bandeja (pendiente o aceptada).
        app.MapGet("/descargas/datos/solicitud/{id:int}", async (int id, bool? inline, InboxService inbox, PackageLibrary library, HttpContext http, CancellationToken ct) =>
        {
            var r = await inbox.GetAsync(id, ct);
            var zip = r is null ? null : await inbox.ReadZipAsync(r, ct);
            if (zip is null)
            {
                return Results.NotFound("Solicitud sin paquete.");
            }

            var v = await library.ValidateForStorageAsync(zip, ct);
            return Content(http, v.Data, v.Manifest, inline == true);
        }).ExcludeFromDescription();

        app.MapGet("/descargas/original/{id:int}", async (int id, bool? inline, PackageLibrary library, HttpContext http, CancellationToken ct) =>
        {
            var p = await library.GetAsync(id, ct);
            if (p?.StoragePath is null || p.PacketType != ProtocolConstants.PacketTypeResult)
            {
                return Results.NotFound("Resultado no encontrado.");
            }

            try
            {
                var zip = await library.ReadZipAsync(p, ct);
                var v = await library.ValidateForStorageAsync(zip, ct);
                var original = await library.OpenResultAsync(zip, ct);
                return Content(http, original, v.Manifest, inline == true);
            }
            catch (ProtocolException ex)
            {
                return Results.Problem(ex.Message, statusCode: StatusCodes.Status422UnprocessableEntity, title: ex.Code);
            }
        }).ExcludeFromDescription();
    }

    /// <summary>
    /// En línea solo para texto plano e imágenes raster (detectadas por bytes); todo lo demás se descarga.
    /// <c>nosniff</c> evita que el navegador reinterprete el contenido.
    /// </summary>
    private static IResult Content(HttpContext http, byte[] data, Manifest m, bool inline)
    {
        var name = string.IsNullOrWhiteSpace(m.OriginalFileName) ? "contenido.bin" : Path.GetFileName(m.OriginalFileName);
        var (type, mime) = PreviewKind.Detect(data, m.ContentType, m.PayloadMode, name);
        http.Response.Headers.XContentTypeOptions = "nosniff";
        if (inline && type != PreviewType.Binary)
        {
            http.Response.Headers.ContentSecurityPolicy = "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'";
            return Results.File(data, mime);
        }

        return Results.File(data, type == PreviewType.Binary ? ContentTypes.ForFile(name, ProtocolConstants.PayloadFile) : mime, name);
    }
}
