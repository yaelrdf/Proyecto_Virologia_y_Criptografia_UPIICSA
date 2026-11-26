using CentroCiber.Infrastructure.Configuration;
using CentroCiber.Infrastructure.Data;
using CentroCiber.Web.Components;
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

        var dataPath = options.ResolveDataPath(builder.Environment.ContentRootPath);
        Directory.CreateDirectory(dataPath);
        builder.Services.AddDbContextFactory<CentroCiberDbContext>(o =>
            o.UseSqlite($"Data Source={Path.Combine(dataPath, options.DatabaseFileName)}"));

        builder.WebHost.ConfigureKestrel(k =>
        {
            k.Limits.MaxRequestBodySize = Crypto.Protocol.ProtocolConstants.MaxBodyBytes;
            k.ListenAnyIP(options.EffectiveHttpPort);
        });

        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddControllers();
        if (options.EnableUi)
        {
            builder.Services.AddRazorComponents().AddInteractiveServerComponents();
        }

        var app = builder.Build();

        using (var scope = app.Services.CreateScope())
        {
            var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<CentroCiberDbContext>>();
            using var db = factory.CreateDbContext();
            db.Database.Migrate();
        }

        app.MapControllers();
        if (options.EnableUi)
        {
            app.UseAntiforgery();
            app.MapStaticAssets();
            app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
        }

        return app;
    }
}
