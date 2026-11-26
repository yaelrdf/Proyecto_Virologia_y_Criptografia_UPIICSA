using CentroCiber.Application.Providers;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Infrastructure.Data.Entities;

namespace CentroCiber.Application.Services;

/// <summary>Resultado de una operación iniciada desde la interfaz.</summary>
public sealed record OperationOutcome(OperationResult Result, PackageEntity? Stored, string Summary);

/// <summary>
/// Orquesta las operaciones de la interfaz: algoritmo propio → local; ajeno → dueño remoto.
/// Guarda en Consultas los paquetes (<c>Generado</c>) y resultados (<c>Resultado</c>).
/// </summary>
public sealed class OperationsService(
    NodeContext node,
    LocalAlgorithmProvider local,
    RemoteAlgorithmProvider remote,
    PackageLibrary library)
{
    public bool IsLocal(string code) => local.CanHandle(code);

    public Task<ProviderAvailability> AvailabilityAsync(AlgorithmInfo info, CancellationToken ct = default) =>
        remote.GetAvailabilityAsync(info, ct);

    public async Task<IReadOnlyList<ProviderAvailability>> AllAvailabilityAsync(CancellationToken ct = default)
    {
        var list = new List<ProviderAvailability>();
        foreach (var info in AlgorithmCatalog.All)
        {
            list.Add(await remote.GetAvailabilityAsync(info, ct));
        }

        return list;
    }

    public async Task<OperationOutcome> ForwardAsync(ForwardRequest request, CancellationToken ct = default)
    {
        var result = local.CanHandle(request.AlgorithmCode)
            ? await local.ForwardAsync(request, ct)
            : await remote.ForwardAsync(request, ct);
        if (result.IsPending)
        {
            return new OperationOutcome(result, null, $"{result.ProviderNode} aceptó el trabajo {result.PendingJobId}; consulta su estado en Consultas.");
        }

        var stored = await library.SaveAsync(result.Zip!, result.FileName!, result.Manifest!, PackageOrigins.Generated, ct);
        return new OperationOutcome(result, stored, $"Paquete {result.FileName} generado por {result.ProviderNode}.");
    }

    public async Task<OperationOutcome> InverseAsync(InverseRequest request, CancellationToken ct = default)
    {
        var result = local.CanHandle(request.AlgorithmCode)
            ? await local.InverseAsync(request, ct)
            : await remote.InverseAsync(request, ct);
        if (result.IsPending)
        {
            return new OperationOutcome(result, null, $"{result.ProviderNode} aceptó el trabajo {result.PendingJobId}.");
        }

        var stored = await library.SaveAsync(result.Zip!, result.FileName!, result.Manifest!, PackageOrigins.Result, ct);
        var verdict = result.Manifest!.Verification is { } v ? (v.Valid ? " Verificación: válida." : " Verificación: NO válida.") : string.Empty;
        return new OperationOutcome(result, stored, $"Resultado {result.FileName} de {result.ProviderNode}.{verdict}");
    }

    /// <summary>Consulta un trabajo remoto pendiente; si terminó, lo guarda y devuelve el resultado.</summary>
    public async Task<OperationOutcome?> CompletePendingAsync(string providerNode, string jobId, string requestId, string operation, CancellationToken ct = default)
    {
        var zip = await remote.TryFetchJobAsync(providerNode, jobId, requestId, ct);
        if (zip is null)
        {
            return null;
        }

        if (operation == ProtocolConstants.OperationInverse)
        {
            var r = await remote.CompleteInverseAsync(zip, providerNode, requestId, ct);
            var stored = await library.SaveAsync(zip, r.FileName!, r.Manifest!, PackageOrigins.Result, ct);
            return new OperationOutcome(r, stored, $"Resultado {r.FileName} recibido.");
        }

        var validated = await library.ValidateForStorageAsync(zip, ct);
        var storedPkg = await library.SaveAsync(zip, Packaging.PackageNaming.FileName(validated.Manifest), validated.Manifest, PackageOrigins.Generated, ct);
        return new OperationOutcome(new OperationResult { Zip = zip, Manifest = validated.Manifest, ProviderNode = providerNode }, storedPkg, "Paquete recibido.");
    }

    public Task<Packaging.Contracts.ReceiveResponse> SendToInboxAsync(string targetNode, byte[] zip, CancellationToken ct = default) =>
        remote.SendToInboxAsync(targetNode, zip, ct);

    public string NodeId => node.NodeId;
}
