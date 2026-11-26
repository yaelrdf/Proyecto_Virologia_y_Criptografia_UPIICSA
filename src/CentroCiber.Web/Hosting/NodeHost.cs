using CentroCiber.Application;
using CentroCiber.Application.Services;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Infrastructure.Configuration;
using CentroCiber.Infrastructure.Data;
using CentroCiber.Web.Api;
using CentroCiber.Web.Components;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;

namespace CentroCiber.Web.Hosting;

/// <summary>Construcción del host del nodo (compartida por <c>Program</c> y las pruebas).</summary>
public static class NodeHost
{
    public const string EnvironmentPrefix = "CC_";

    public static WebApplication Build(string[] args, Action<WebApplicationBuilder>? configure = null)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.Configuration.AddEnvironmentVariables(EnvironmentPrefix);
        configure?.Invoke(builder);

        var options = builder.Configuration.GetSection(NodeOptions.SectionName).Get<NodeOptions>() ?? new NodeOptions();
        builder.Services.Configure<NodeOptions>(builder.Configuration.GetSection(NodeOptions.SectionName));
        var clock = TimeProvider.System;

        // Datos: carpeta, base de datos (migrada antes de configurar Kestrel) y ajustes.
        var dataPath = options.ResolveDataPath(builder.Environment.ContentRootPath);
        Directory.CreateDirectory(dataPath);
        var connection = $"Data Source={Path.Combine(dataPath, options.DatabaseFileName)}";
        var dbOptions = new DbContextOptionsBuilder<CentroCiberDbContext>().UseSqlite(connection).Options;
        bool httpsSetting;
        using (var db = new CentroCiberDbContext(dbOptions))
        {
            db.Database.Migrate();
            httpsSetting = db.Settings.AsNoTracking().Single(s => s.Id == 1).HttpsEnabled;
        }

        builder.Services.AddDbContextFactory<CentroCiberDbContext>(o => o.UseSqlite(connection));

        // Identidad: PFX protegido con CC_PFX_PASSWORD (o user-secrets PFX_PASSWORD en desarrollo).
        var password = builder.Configuration[NodeOptions.PfxPasswordKey];
        if (string.IsNullOrEmpty(password))
        {
            throw new InvalidOperationException(
                "Falta la contraseña del certificado. Define la variable de entorno CC_PFX_PASSWORD " +
                "(o 'dotnet user-secrets set PFX_PASSWORD <valor>' en desarrollo).");
        }

        var identity = NodeIdentity.LoadOrCreate(Path.Combine(dataPath, options.PfxFileName), password, options.TeamNumber, clock, out _);
        if (identity.NodeId != options.NodeId)
        {
            throw new InvalidOperationException(
                $"El PFX pertenece a {identity.NodeId} pero el nodo está configurado como {options.NodeId}. Usa otra carpeta de datos.");
        }

        var httpsActive = options.HttpsEnabled && httpsSetting;
        var context = new NodeContext(options, identity, dataPath, httpsActive, clock);

        builder.WebHost.ConfigureKestrel(k =>
        {
            k.Limits.MaxRequestBodySize = ProtocolConstants.MaxBodyBytes + (1024 * 1024);
            k.ListenAnyIP(options.EffectiveHttpPort);
            if (httpsActive)
            {
                k.ListenAnyIP(options.EffectiveHttpsPort, l => l.UseHttps(context.Identity.Certificate));
            }
        });
        builder.Services.Configure<FormOptions>(f =>
        {
            f.MultipartBodyLengthLimit = ProtocolConstants.MaxBodyBytes + (1024 * 1024);
            f.ValueLengthLimit = (int)ProtocolConstants.MaxBodyBytes;
        });

        builder.Services.AddCentroCiberApplication(context);
        builder.Services.AddProtocolApi();
        if (options.EnableUi)
        {
            builder.Services.AddRazorComponents().AddInteractiveServerComponents();
        }

        var app = builder.Build();
        app.Services.GetRequiredService<NodeDirectory>().SyncSelfAsync().GetAwaiter().GetResult();

        if (options.UiLanOnly)
        {
            app.UseMiddleware<Middleware.LanOnlyMiddleware>();
        }

        app.UseProtocolApi();
        app.MapOpenApi("/openapi/{documentName}.json");
        app.MapControllers();
        if (options.EnableUi)
        {
            app.UseAntiforgery();
            app.MapStaticAssets();
            app.MapDownloads();
            app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
        }

        return app;
    }
}
