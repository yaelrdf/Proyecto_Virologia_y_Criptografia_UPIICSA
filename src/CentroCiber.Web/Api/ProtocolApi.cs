using System.Text.Json;
using CentroCiber.Application;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Packaging;
using CentroCiber.Packaging.Contracts;
using Microsoft.AspNetCore.Http.Features;

namespace CentroCiber.Web.Api;

/// <summary>Configuración común de la API REST del protocolo (§10, §14).</summary>
public static class ProtocolApi
{
    public const string RequestIdItem = "cc.requestId";

    public static IServiceCollection AddProtocolApi(this IServiceCollection services)
    {
        services.AddControllers()
            .AddApplicationPart(typeof(ProtocolApi).Assembly)
            .AddJsonOptions(o =>
            {
                o.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
                o.JsonSerializerOptions.Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
            })
            .ConfigureApiBehaviorOptions(o => o.SuppressModelStateInvalidFilter = true);
        services.AddOpenApi(o =>
        {
            o.AddDocumentTransformer((doc, _, _) =>
            {
                doc.Info = new()
                {
                    Title = "API del nodo EQ08 · Centro de Ciberseguridad Comunitario",
                    Version = ProtocolConstants.ProtocolVersion,
                    Description = "Endpoints del Estándar de Comunicación v2.0 (§10). Los errores usan application/problem+json con los códigos del Anexo B.",
                };
                return Task.CompletedTask;
            });
        });
        services.AddSingleton<CryptoConcurrencyLimiter>();
        return services;
    }

    public static WebApplication UseProtocolApi(this WebApplication app)
    {
        app.Use(async (ctx, next) =>
        {
            if (!ctx.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase))
            {
                await next();
                return;
            }

            var node = ctx.RequestServices.GetRequiredService<NodeContext>();
            ctx.Response.Headers[ProtocolConstants.HeaderNode] = node.NodeId;
            ctx.Response.Headers[ProtocolConstants.HeaderProtocol] = ProtocolConstants.ProtocolVersion;
            var limiter = ctx.RequestServices.GetRequiredService<CryptoConcurrencyLimiter>();
            var limited = ctx.Request.Path.StartsWithSegments("/api/crypto", StringComparison.OrdinalIgnoreCase);
            try
            {
                if (limited && !limiter.TryEnter())
                {
                    throw new ProtocolException(ErrorCodes.Busy, "El nodo tiene demasiadas peticiones simultáneas; intenta más tarde.");
                }

                try
                {
                    await next();
                    if (!ctx.Response.HasStarted && ctx.Response.StatusCode == StatusCodes.Status415UnsupportedMediaType)
                    {
                        await WriteProblemAsync(ctx, ErrorCodes.UnsupportedMedia, "Se esperaba multipart/form-data.");
                    }
                }
                finally
                {
                    if (limited)
                    {
                        limiter.Exit();
                    }
                }
            }
            catch (ProtocolException ex) when (!ctx.Response.HasStarted)
            {
                await WriteProblemAsync(ctx, ex.Code, ex.Message);
            }
            catch (BadHttpRequestException ex) when (!ctx.Response.HasStarted)
            {
                if (ex.StatusCode == StatusCodes.Status413PayloadTooLarge)
                {
                    await WriteProblemAsync(ctx, ErrorCodes.Size, "El cuerpo de la petición supera 50 MB.");
                }
                else
                {
                    await WriteProblemAsync(ctx, ErrorCodes.Request, "Petición HTTP mal formada.");
                }
            }
            catch (InvalidDataException) when (!ctx.Response.HasStarted)
            {
                await WriteProblemAsync(ctx, ErrorCodes.Request, "El cuerpo multipart/form-data no es válido o excede los límites.");
            }
            catch (Exception ex) when (!ctx.Response.HasStarted && ex is not OperationCanceledException)
            {
                ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("CentroCiber.Api")
                    .LogError(ex, "Error interno en {Path}", ctx.Request.Path.Value);
                await WriteProblemAsync(ctx, ErrorCodes.Internal, "Error interno del proveedor.");
            }
        });
        return app;
    }

    public static async Task WriteProblemAsync(HttpContext ctx, string code, string detail)
    {
        var def = ErrorCodes.Get(code);
        var node = ctx.RequestServices.GetRequiredService<NodeContext>();
        var requestId = ctx.Items.TryGetValue(RequestIdItem, out var rid) ? rid as string
            : ctx.Request.Headers[ProtocolConstants.HeaderRequestId].FirstOrDefault();
        var problem = new ProblemDocument
        {
            Type = ProtocolConstants.ErrorTypeBase + def.Code,
            Title = def.Title,
            Status = def.HttpStatus,
            Code = def.Code,
            Detail = detail,
            NodeId = node.NodeId,
            RequestId = Identifiers.IsUuidV4(requestId) ? requestId : null,
            TimestampUtc = Identifiers.FormatTimestamp(node.Clock.GetUtcNow()),
        };
        ctx.Response.StatusCode = def.HttpStatus;
        ctx.Response.ContentType = ProtocolConstants.ProblemContentType;
        await ctx.Response.WriteAsync(JsonSerializer.Serialize(problem, ProtocolJson.Compact));
    }

    /// <summary>Lee una parte del multipart como bytes exactos (archivo o campo de texto).</summary>
    public static async Task<byte[]?> ReadPartAsync(IFormCollection form, string name, CancellationToken ct)
    {
        var file = form.Files.GetFile(name);
        if (file is not null)
        {
            using var ms = new MemoryStream();
            await file.CopyToAsync(ms, ct);
            return ms.ToArray();
        }

        return form.TryGetValue(name, out var value) && value.Count > 0
            ? System.Text.Encoding.UTF8.GetBytes(value.ToString())
            : null;
    }

    public static async Task<IFormCollection> ReadFormAsync(HttpRequest request, CancellationToken ct)
    {
        if (!request.HasFormContentType || request.ContentType?.StartsWith("multipart/form-data", StringComparison.OrdinalIgnoreCase) != true)
        {
            throw new ProtocolException(ErrorCodes.UnsupportedMedia, "Se esperaba multipart/form-data.");
        }

        if (request.ContentLength > ProtocolConstants.MaxBodyBytes + (1024 * 1024))
        {
            throw new ProtocolException(ErrorCodes.Size, "El cuerpo de la petición supera 50 MB.");
        }

        var feature = request.HttpContext.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (feature is { IsReadOnly: false })
        {
            feature.MaxRequestBodySize = ProtocolConstants.MaxBodyBytes + (1024 * 1024);
        }

        return await request.ReadFormAsync(ct);
    }
}

/// <summary>Límite de peticiones <c>/api/crypto/*</c> simultáneas (§13.3 → <c>E-BUSY</c>).</summary>
public sealed class CryptoConcurrencyLimiter(NodeContext node)
{
    private int active;

    public int Active => Volatile.Read(ref active);

    public bool TryEnter()
    {
        if (Interlocked.Increment(ref active) > node.Options.MaxConcurrentCryptoRequests)
        {
            Interlocked.Decrement(ref active);
            return false;
        }

        return true;
    }

    public void Exit() => Interlocked.Decrement(ref active);
}
