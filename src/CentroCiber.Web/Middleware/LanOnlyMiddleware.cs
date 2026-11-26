using System.Net;
using CentroCiber.Infrastructure.Network;

namespace CentroCiber.Web.Middleware;

/// <summary>
/// Filtro solo-LAN (plan §5): la interfaz web (todo lo que no es <c>/api</c>) solo responde a
/// loopback y a direcciones privadas (10/8, 172.16/12, 192.168/16, enlace local). La API sí
/// responde a cualquier IP de la LAN (§5.1).
/// </summary>
public sealed class LanOnlyMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase)
            && !IsAllowed(context.Connection.RemoteIpAddress))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "text/plain; charset=utf-8";
            await context.Response.WriteAsync("La interfaz de este nodo solo está disponible desde la red local.");
            return;
        }

        await next(context);
    }

    /// <summary>Nulo ocurre con el servidor de pruebas en memoria; se trata como local.</summary>
    public static bool IsAllowed(IPAddress? remote) => remote is null || NetworkInfo.IsPrivateOrLoopback(remote);
}
