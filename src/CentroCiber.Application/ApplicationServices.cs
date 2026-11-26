using CentroCiber.Application.Jobs;
using CentroCiber.Application.Notifications;
using CentroCiber.Application.Providers;
using CentroCiber.Application.Services;
using CentroCiber.Crypto.Algorithms;
using CentroCiber.Packaging;
using Microsoft.Extensions.DependencyInjection;

namespace CentroCiber.Application;

/// <summary>Registro de servicios de la capa de aplicación.</summary>
public static class ApplicationServices
{
    public static IServiceCollection AddCentroCiberApplication(this IServiceCollection services, NodeContext context)
    {
        services.AddSingleton(context);
        services.AddSingleton(context.Clock);
        services.AddSingleton<NotificationHub>();
        services.AddSingleton<ILocalAlgorithm, HashShaAlgorithm>();
        services.AddSingleton<ILocalAlgorithm, HmacSha256Algorithm>();
        services.AddSingleton<IReplayGuard, DbReplayGuard>();
        services.AddSingleton<NodeDirectory>();
        services.AddSingleton<ITrustLookup>(sp => sp.GetRequiredService<NodeDirectory>());
        services.AddSingleton<PackageValidator>();
        services.AddSingleton<SettingsService>();
        services.AddSingleton<AuditService>();
        services.AddSingleton<LocalAlgorithmProvider>();
        services.AddSingleton<JobQueue>();
        services.AddSingleton<CryptoRequestHandler>();
        services.AddSingleton<PackageLibrary>();
        services.AddSingleton<InboxService>();
        return services;
    }
}
