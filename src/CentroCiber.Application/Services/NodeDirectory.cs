using CentroCiber.Crypto.Protocol;
using CentroCiber.Infrastructure.Data;
using CentroCiber.Infrastructure.Data.Entities;
using CentroCiber.Packaging;
using Microsoft.EntityFrameworkCore;

namespace CentroCiber.Application.Services;

/// <summary>Directorio local de nodos (§6.4) con confianza en el primer uso (§6.3).</summary>
public partial class NodeDirectory(
    IDbContextFactory<CentroCiberDbContext> dbf,
    NodeContext node,
    Notifications.NotificationHub hub) : ITrustLookup
{
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
        foreach (var stale in await db.Nodes.Where(n => n.IsSelf && n.NodeId != node.NodeId).ToListAsync(ct))
        {
            db.Nodes.Remove(stale);
        }

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

    /// <summary>ADR 0006: un solicitante no fijado queda registrado como pendiente de confirmar.</summary>
    public async Task RegisterRequesterAsync(string nodeId, string? ip, string certificatePem, string thumbprint, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var entity = await db.Nodes.FirstOrDefaultAsync(n => n.NodeId == nodeId, ct);
        if (entity is null)
        {
            var team = int.Parse(nodeId.AsSpan(2), System.Globalization.CultureInfo.InvariantCulture);
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
            hub.Publish(new Notifications.NodeEvent(Notifications.NodeEventKind.NodeDiscovered,
                $"{nodeId} hizo una petición; confirma su huella en Nodos.", node.Clock.GetUtcNow(), nodeId));
        }
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
}
