using CentroCiber.Application.Services;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Packaging;

namespace CentroCiber.Web.Api;

/// <summary>Descargas de la interfaz (solo LAN): zip de Consultas y original de un resultado.</summary>
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

        app.MapGet("/descargas/original/{id:int}", async (int id, PackageLibrary library, CancellationToken ct) =>
        {
            var p = await library.GetAsync(id, ct);
            if (p?.StoragePath is null || p.PacketType != ProtocolConstants.PacketTypeResult)
            {
                return Results.NotFound("Resultado no encontrado.");
            }

            try
            {
                var original = await library.OpenResultAsync(await library.ReadZipAsync(p, ct), ct);
                var name = string.IsNullOrWhiteSpace(p.OriginalFileName) ? "original.bin" : Path.GetFileName(p.OriginalFileName);
                return Results.File(original, ContentTypes.ForFile(name, ProtocolConstants.PayloadFile), name);
            }
            catch (ProtocolException ex)
            {
                return Results.Problem(ex.Message, statusCode: StatusCodes.Status422UnprocessableEntity, title: ex.Code);
            }
        }).ExcludeFromDescription();
    }
}
