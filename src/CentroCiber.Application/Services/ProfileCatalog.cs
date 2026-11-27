using System.Text.Json;
using CentroCiber.Application.Providers;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Packaging.Contracts;

namespace CentroCiber.Application.Services;

/// <summary>
/// Perfiles de algoritmos para construir formularios (§10.4 "DEBERÍAN construir el formulario a partir del perfil"):
/// propios desde el proveedor local; ajenos desde el <c>GET /api/algorithms</c> del dueño en caché;
/// si no hay, el mínimo de la tabla 4.2.
/// </summary>
public sealed class ProfileCatalog(LocalAlgorithmProvider local, SettingsService settings, NodeDirectory directory, RemoteAlgorithmProvider remote)
{
    public async Task<(AlgorithmProfile Profile, string Source)> GetAsync(string code, CancellationToken ct = default)
    {
        var info = AlgorithmCatalog.ByCode(code) ?? throw new ArgumentException("Algoritmo desconocido.", nameof(code));
        var own = local.Algorithms.FirstOrDefault(a => a.Code == code);
        if (own is not null)
        {
            return (AlgorithmProfiles.For(own, await settings.EnabledVariantsAsync(ct)), "perfil propio");
        }

        var availability = await remote.GetAvailabilityAsync(info, ct);
        if (availability.ProviderNode is { } owner && await directory.FindAsync(owner, ct) is { ProfileJson: { } json })
        {
            try
            {
                var profiles = JsonSerializer.Deserialize<AlgorithmsResponse>(json);
                var p = profiles?.Algorithms.FirstOrDefault(a => a.AlgorithmCode == code);
                if (p is not null)
                {
                    return (p, $"perfil publicado por {owner}");
                }
            }
            catch (JsonException)
            {
                // Perfil ajeno mal formado: se usa el mínimo de la tabla 4.2.
            }
        }

        return (AlgorithmProfiles.Generic(info), "mínimo de la tabla 4.2 (el dueño no ha publicado perfil)");
    }
}
