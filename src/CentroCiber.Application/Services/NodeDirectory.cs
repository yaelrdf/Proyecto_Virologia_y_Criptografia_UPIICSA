using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Text.Json;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Discovery;
using CentroCiber.Infrastructure.Data;
using CentroCiber.Infrastructure.Data.Entities;
using CentroCiber.Infrastructure.Http;
using CentroCiber.Infrastructure.Network;
using CentroCiber.Packaging;
using CentroCiber.Packaging.Contracts;
using Microsoft.EntityFrameworkCore;

namespace CentroCiber.Application.Services;

/// <summary>
/// Directorio local de nodos (§6.4) con alta por anuncio, escaneo o manual, verificación
/// (<c>GET /api/status</c> + <c>/api/certificate</c>, CN y huella) y confianza en el primer uso (§6.3).
/// </summary>
public sealed class NodeDirectory(
    IDbContextFactory<CentroCiberDbContext> dbf,
    NodeContext node,
    NodeHttpClientFactory httpFactory,
    Notifications.NotificationHub hub) : ITrustLookup
{
    private static readonly TimeSpan ReverifyEvery = TimeSpan.FromSeconds(60);
    private readonly ConcurrentDictionary<string, DateTimeOffset> lastVerified = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim writeGate = new(1, 1);

    public async Task<string?> GetPinnedThumbprintAsync(string nodeId, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        return await db.Nodes.Where(n => n.NodeId == nodeId && !n.IsSelf)
            .Select(n => n.PinnedThumbprintSha256).FirstOrDefaultAsync(ct);
    }

    public async Task<IReadOnlyList<NodeEntity>> ListAsync(CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        return await db.Nodes.AsNoTracking().OrderBy(n => n.TeamNumber).ToListAsync(ct);
    }

    public async Task<NodeEntity?> FindAsync(string nodeId, CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        return await db.Nodes.AsNoTracking().FirstOrDefaultAsync(n => n.NodeId == nodeId, ct);
    }

    /// <summary>Actualiza la fila propia al arrancar (identidad, puertos, huella).</summary>
    public async Task SyncSelfAsync(CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        db.Nodes.RemoveRange(await db.Nodes.Where(n => n.IsSelf && n.NodeId != node.NodeId).ToListAsync(ct));
        await db.SaveChangesAsync(ct);
        var self = await db.Nodes.FirstOrDefaultAsync(n => n.NodeId == node.NodeId, ct);
        if (self is null)
        {
            self = new NodeEntity
            {
                NodeId = node.NodeId,
                Ip = "127.0.0.1",
                Source = NodeSources.Manual,
                Status = ProtocolConstants.StatusOnline,
                TrustState = TrustStates.Self,
            };
            db.Nodes.Add(self);
        }

        var identity = node.Identity;
        self.IsSelf = true;
        self.TrustState = TrustStates.Self;
        self.TeamNumber = node.TeamNumber;
        self.Ip = node.AdvertisedAddress.ToString();
        self.HttpPort = node.HttpPort;
        self.HttpsPort = node.HttpsPort;
        self.Algorithms = string.Join(',', AlgorithmCatalog.OwnedBy(node.TeamNumber).Select(a => a.Code));
        self.PinnedThumbprintSha256 = identity.Thumbprint;
        self.ObservedThumbprintSha256 = identity.Thumbprint;
        self.CertificatePem = identity.CertificatePem;
        self.Status = ProtocolConstants.StatusOnline;
        self.LastSeenUtc = node.Clock.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Anuncio o escaneo: registra/actualiza la ubicación y verifica si hace falta.</summary>
    public async Task ObserveAsync(string nodeId, string ip, int httpPort, int? httpsPort, string? announcedThumbprint,
        IEnumerable<string> algorithms, string source, string status, CancellationToken ct)
    {
        if (nodeId == node.NodeId)
        {
            return;
        }

        bool needsVerify;
        await writeGate.WaitAsync(ct);
        try
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            var entity = await db.Nodes.FirstOrDefaultAsync(n => n.NodeId == nodeId, ct);
            var isNew = entity is null;
            if (entity is null)
            {
                entity = new NodeEntity
                {
                    NodeId = nodeId,
                    Ip = ip,
                    Source = source,
                    Status = status,
                    TrustState = TrustStates.Pending,
                };
                db.Nodes.Add(entity);
            }

            var wasOnline = entity.Status == ProtocolConstants.StatusOnline;
            entity.TeamNumber = int.Parse(nodeId.AsSpan(2), CultureInfo.InvariantCulture);
            entity.Ip = ip;
            entity.HttpPort = httpPort;
            entity.HttpsPort = httpsPort;
            entity.Algorithms = string.Join(',', algorithms);
            entity.Status = status;
            entity.LastSeenUtc = node.Clock.GetUtcNow().UtcDateTime;
            if (entity.Source == NodeSources.Request)
            {
                entity.Source = source;
            }

            await db.SaveChangesAsync(ct);
            needsVerify = status == ProtocolConstants.StatusOnline
                && (isNew || announcedThumbprint != entity.ObservedThumbprintSha256 || entity.CertificatePem is null
                    || !lastVerified.TryGetValue(nodeId, out var at) || node.Clock.GetUtcNow() - at > ReverifyEvery);
            if (isNew)
            {
                hub.Publish(new Notifications.NodeEvent(Notifications.NodeEventKind.NodeDiscovered,
                    $"Nodo {nodeId} encontrado ({source}) en {ip}:{httpPort}.", node.Clock.GetUtcNow(), nodeId));
            }
            else if (wasOnline != (status == ProtocolConstants.StatusOnline))
            {
                hub.Publish(new Notifications.NodeEvent(Notifications.NodeEventKind.NodeStatusChanged,
                    $"{nodeId} está {status}.", node.Clock.GetUtcNow(), nodeId));
            }
        }
        finally
        {
            writeGate.Release();
        }

        if (needsVerify)
        {
            await VerifyAsync(nodeId, announcedThumbprint, ct);
        }
    }

    /// <summary>
    /// §6.3 pasos 2–5: consulta status y certificado, comprueba CN = nodeId y que la huella coincida
    /// con la anunciada; actualiza el estado de confianza y alerta si cambió la huella fijada.
    /// </summary>
    public async Task<NodeEntity?> VerifyAsync(string nodeId, string? announcedThumbprint = null, CancellationToken ct = default)
    {
        var current = await FindAsync(nodeId, ct);
        if (current is null || current.IsSelf)
        {
            return current;
        }

        string? error = null;
        StatusResponse? status = null;
        string? pem = null;
        string? thumbprint = null;
        string? profile = null;
        try
        {
            using var http = httpFactory.CreatePlain();
            http.Timeout = TimeSpan.FromSeconds(5);
            var baseUri = new Uri($"http://{current.Ip}:{current.HttpPort}");
            status = JsonSerializer.Deserialize<StatusResponse>(await http.GetStringAsync(new Uri(baseUri, "/api/status"), ct))
                ?? throw new InvalidOperationException("status vacío");
            pem = await http.GetStringAsync(new Uri(baseUri, "/api/certificate"), ct);
            if (status.NodeId != nodeId)
            {
                throw new ProtocolException(ErrorCodes.Cert, $"El nodo en {current.Ip}:{current.HttpPort} es {status.NodeId}, no {nodeId}.");
            }

            using var cert = CertificateTools.LoadAndValidate(pem, nodeId, node.Clock.GetUtcNow());
            thumbprint = CertificateTools.Thumbprint(cert);
            if (thumbprint != status.CertificateThumbprintSha256 || (announcedThumbprint is not null && thumbprint != announcedThumbprint))
            {
                throw new ProtocolException(ErrorCodes.CertThumbprint, "La huella del certificado no coincide con la anunciada.");
            }

            try
            {
                profile = await http.GetStringAsync(new Uri(baseUri, "/api/algorithms"), ct);
            }
            catch (HttpRequestException)
            {
                profile = null;
            }
        }
        catch (ProtocolException ex)
        {
            error = ex.Message;
            thumbprint = null;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException)
        {
            await SetErrorAsync(nodeId, "Sin respuesta de status/certificate: " + ex.Message, ct);
            return await FindAsync(nodeId, ct);
        }

        await writeGate.WaitAsync(ct);
        try
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            var entity = await db.Nodes.FirstAsync(n => n.NodeId == nodeId, ct);
            if (error is not null)
            {
                entity.TrustState = entity.PinnedThumbprintSha256 is null ? TrustStates.Invalid : entity.TrustState;
                entity.LastError = error;
            }
            else
            {
                entity.CertificatePem = pem;
                entity.ObservedThumbprintSha256 = thumbprint;
                entity.Algorithms = string.Join(',', status!.Algorithms.Select(a => a.AlgorithmCode));
                entity.HttpPort = status.HttpPort;
                entity.HttpsPort = status.HttpsPort;
                entity.ProfileJson = profile ?? entity.ProfileJson;
                entity.Status = ProtocolConstants.StatusOnline;
                entity.LastSeenUtc = node.Clock.GetUtcNow().UtcDateTime;
                entity.LastError = null;
                var previous = entity.TrustState;
                entity.TrustState = entity.PinnedThumbprintSha256 is null ? TrustStates.Pending
                    : entity.PinnedThumbprintSha256 == thumbprint ? TrustStates.Pinned
                    : TrustStates.ThumbprintChanged;
                if (entity.TrustState == TrustStates.ThumbprintChanged && previous != TrustStates.ThumbprintChanged)
                {
                    hub.Publish(new Notifications.NodeEvent(Notifications.NodeEventKind.ThumbprintChanged,
                        $"¡Alerta! La huella de {nodeId} cambió. No se usará hasta que la aceptes de nuevo.", node.Clock.GetUtcNow(), nodeId));
                }

                lastVerified[nodeId] = node.Clock.GetUtcNow();
            }

            await db.SaveChangesAsync(ct);
            return entity;
        }
        finally
        {
            writeGate.Release();
        }
    }

    /// <summary>Alta manual (IP + puerto), §6.3 #1. Debe existir siempre.</summary>
    public async Task<NodeEntity> AddManualAsync(string ip, int port, CancellationToken ct = default)
    {
        if (!IPAddress.TryParse(ip, out _) || port is <= 0 or > 65535)
        {
            throw new ArgumentException("IP o puerto inválidos.");
        }

        using var http = httpFactory.CreatePlain();
        http.Timeout = TimeSpan.FromSeconds(5);
        StatusResponse status;
        try
        {
            status = JsonSerializer.Deserialize<StatusResponse>(await http.GetStringAsync(new Uri($"http://{ip}:{port}/api/status"), ct))
                ?? throw new InvalidOperationException("Respuesta vacía.");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            throw new InvalidOperationException($"No respondió GET /api/status en {ip}:{port}: {ex.Message}", ex);
        }

        if (!Identifiers.IsNodeId(status.NodeId))
        {
            throw new InvalidOperationException("La respuesta no tiene un nodeId válido.");
        }

        if (status.NodeId == node.NodeId)
        {
            throw new InvalidOperationException("Ese es este mismo nodo.");
        }

        await ObserveAsync(status.NodeId, ip, status.HttpPort, status.HttpsPort, status.CertificateThumbprintSha256,
            status.Algorithms.Select(a => a.AlgorithmCode), NodeSources.Manual, ProtocolConstants.StatusOnline, ct);
        await VerifyAsync(status.NodeId, status.CertificateThumbprintSha256, ct);
        return (await FindAsync(status.NodeId, ct))!;
    }

    /// <summary>TOFU: el usuario confirma la huella observada; desde ahí queda fijada (§6.3 #4–#5).</summary>
    public async Task<NodeEntity> ConfirmAsync(string nodeId, CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var entity = await db.Nodes.FirstOrDefaultAsync(n => n.NodeId == nodeId && !n.IsSelf, ct)
            ?? throw new InvalidOperationException("Nodo no encontrado.");
        if (entity.ObservedThumbprintSha256 is null || entity.TrustState == TrustStates.Invalid)
        {
            throw new InvalidOperationException("El nodo no tiene una huella verificada que confirmar.");
        }

        entity.PinnedThumbprintSha256 = entity.ObservedThumbprintSha256;
        entity.TrustState = TrustStates.Pinned;
        entity.LastError = null;
        await db.SaveChangesAsync(ct);
        return entity;
    }

    public async Task RemoveAsync(string nodeId, CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        db.Nodes.RemoveRange(await db.Nodes.Where(n => n.NodeId == nodeId && !n.IsSelf).ToListAsync(ct));
        await db.SaveChangesAsync(ct);
    }

    /// <summary>§6.1: <c>offline</c> si no hay anuncio ni respuesta en 90 s.</summary>
    public async Task<int> MarkStaleOfflineAsync(CancellationToken ct = default)
    {
        var limit = (node.Clock.GetUtcNow() - ProtocolConstants.OfflineAfter).UtcDateTime;
        await using var db = await dbf.CreateDbContextAsync(ct);
        var stale = await db.Nodes.Where(n => !n.IsSelf && n.Status == ProtocolConstants.StatusOnline
            && (n.LastSeenUtc == null || n.LastSeenUtc < limit)).ToListAsync(ct);
        foreach (var n in stale)
        {
            n.Status = ProtocolConstants.StatusOffline;
            hub.Publish(new Notifications.NodeEvent(Notifications.NodeEventKind.NodeStatusChanged,
                $"{n.NodeId} está fuera de línea (90 s sin señal).", node.Clock.GetUtcNow(), n.NodeId));
        }

        await db.SaveChangesAsync(ct);
        return stale.Count;
    }

    /// <summary>Consulta <c>GET /api/status</c> de los nodos silenciosos para mantenerlos en línea.</summary>
    public async Task ProbeQuietNodesAsync(TimeSpan quietFor, CancellationToken ct = default)
    {
        var limit = (node.Clock.GetUtcNow() - quietFor).UtcDateTime;
        var quiet = (await ListAsync(ct)).Where(n => !n.IsSelf && n.Status == ProtocolConstants.StatusOnline
            && (n.LastSeenUtc is null || n.LastSeenUtc < limit)).ToList();
        using var http = httpFactory.CreatePlain();
        http.Timeout = TimeSpan.FromSeconds(2);
        foreach (var n in quiet)
        {
            try
            {
                using var r = await http.GetAsync(new Uri($"http://{n.Ip}:{n.HttpPort}/api/status"), ct);
                if (r.IsSuccessStatusCode)
                {
                    await TouchAsync(n.NodeId, ct);
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                // Sigue silencioso; MarkStaleOfflineAsync decidirá.
            }
        }
    }

    /// <summary>
    /// Escaneo HTTP (§6.2) de la /24 de cada interfaz (y de loopback) en los puertos configurados.
    /// </summary>
    public async Task<IReadOnlyList<ScanHit>> ScanAsync(SubnetScanner scanner, IEnumerable<IPAddress>? hosts = null, CancellationToken ct = default)
    {
        var targets = hosts?.ToList() ?? NetworkInfo.Interfaces().SelectMany(i => SubnetScanner.Slash24(i.Address))
            .Append(IPAddress.Loopback).Distinct().ToList();
        var d = node.Options.Discovery;
        var hits = await scanner.ScanAsync(targets, d.ScanPortFrom, d.ScanPortTo, ct);
        foreach (var hit in hits.Where(h => h.NodeId != node.NodeId))
        {
            var status = JsonSerializer.Deserialize<StatusResponse>(hit.StatusJson);
            if (status is null)
            {
                continue;
            }

            await ObserveAsync(hit.NodeId, hit.Address.ToString(), status.HttpPort, status.HttpsPort, status.CertificateThumbprintSha256,
                status.Algorithms.Select(a => a.AlgorithmCode), NodeSources.Scan, ProtocolConstants.StatusOnline, ct);
        }

        return hits.Where(h => h.NodeId != node.NodeId).ToList();
    }

    /// <summary>ADR 0006: un solicitante no fijado queda registrado como pendiente de confirmar.</summary>
    public async Task RegisterRequesterAsync(string nodeId, string? ip, string certificatePem, string thumbprint, CancellationToken ct)
    {
        await writeGate.WaitAsync(ct);
        try
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            if (await db.Nodes.AnyAsync(n => n.NodeId == nodeId, ct))
            {
                return;
            }

            var team = int.Parse(nodeId.AsSpan(2), CultureInfo.InvariantCulture);
            db.Nodes.Add(new NodeEntity
            {
                NodeId = nodeId,
                TeamNumber = team,
                Ip = ip ?? "desconocida",
                HttpPort = ProtocolConstants.HttpPortFor(team),
                Source = NodeSources.Request,
                Status = ProtocolConstants.StatusOnline,
                TrustState = TrustStates.Pending,
                ObservedThumbprintSha256 = thumbprint,
                CertificatePem = certificatePem,
                LastSeenUtc = node.Clock.GetUtcNow().UtcDateTime,
            });
            await db.SaveChangesAsync(ct);
        }
        finally
        {
            writeGate.Release();
        }

        hub.Publish(new Notifications.NodeEvent(Notifications.NodeEventKind.NodeDiscovered,
            $"{nodeId} hizo una petición; confirma su huella en Nodos.", node.Clock.GetUtcNow(), nodeId));
    }

    public async Task RecordOperationAsync(RemoteOperationEntity op, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var now = node.Clock.GetUtcNow().UtcDateTime;
        op.CreatedUtc = now;
        op.UpdatedUtc = now;
        db.RemoteOperations.Add(op);
        await db.SaveChangesAsync(ct);
    }

    public async Task UpdateOperationAsync(string requestId, string state, string? jobId, string? errorCode, string? errorDetail, int? resultPackageId, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var op = await db.RemoteOperations.OrderByDescending(o => o.Id).FirstOrDefaultAsync(o => o.RequestId == requestId, ct);
        if (op is null)
        {
            return;
        }

        op.State = state;
        op.JobId = jobId ?? op.JobId;
        op.ErrorCode = errorCode;
        op.ErrorDetail = errorDetail;
        op.ResultPackageId = resultPackageId ?? op.ResultPackageId;
        op.UpdatedUtc = node.Clock.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<RemoteOperationEntity>> RecentOperationsAsync(int count, CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        return await db.RemoteOperations.AsNoTracking().OrderByDescending(o => o.Id).Take(count).ToListAsync(ct);
    }

    private async Task TouchAsync(string nodeId, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var e = await db.Nodes.FirstOrDefaultAsync(n => n.NodeId == nodeId, ct);
        if (e is not null)
        {
            e.LastSeenUtc = node.Clock.GetUtcNow().UtcDateTime;
            e.Status = ProtocolConstants.StatusOnline;
            await db.SaveChangesAsync(ct);
        }
    }

    private async Task SetErrorAsync(string nodeId, string error, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var e = await db.Nodes.FirstOrDefaultAsync(n => n.NodeId == nodeId, ct);
        if (e is not null)
        {
            e.LastError = error.Length > 300 ? error[..300] : error;
            await db.SaveChangesAsync(ct);
        }
    }
}
