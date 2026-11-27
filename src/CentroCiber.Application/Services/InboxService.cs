using System.Text.Json;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Infrastructure.Data;
using CentroCiber.Infrastructure.Data.Entities;
using CentroCiber.Packaging;
using CentroCiber.Packaging.Contracts;
using Microsoft.EntityFrameworkCore;

namespace CentroCiber.Application.Services;

/// <summary>Bandeja de Solicitudes (§10.5, §15).</summary>
public sealed class InboxService(
    IDbContextFactory<CentroCiberDbContext> dbf,
    NodeContext node,
    PackageValidator validator,
    PackageLibrary library,
    SettingsService settings,
    AuditService audit,
    Notifications.NotificationHub hub)
{
    public const string FolderInbox = "bandeja";

    /// <summary>Recibe un zip de otro nodo; si pasa §13.1 queda <c>Pendiente</c>.</summary>
    public async Task<ReceiveResponse> ReceiveAsync(byte[] zip, string? remoteIp, CancellationToken ct)
    {
        if (!(await settings.GetAsync(ct)).AcceptingPackages)
        {
            throw new ProtocolException(ErrorCodes.Busy, "Este nodo no está aceptando paquetes en este momento.");
        }

        var report = await validator.ValidateWithReportAsync(zip, PackageValidationOptions.Inbox, ct);
        if (report.Error is { } error)
        {
            await audit.LogAsync("inbox.rejected", null, error.Code, error.Message, ct);
            await RecordInvalidAsync(zip, remoteIp, error, ct);
            throw error;
        }

        var package = report.Package!;
        var m = package.Manifest;
        var path = await node.Store.SaveAsync(FolderInbox, m.PacketId, zip, ct);
        var now = node.Clock.GetUtcNow();
        await using (var db = await dbf.CreateDbContextAsync(ct))
        {
            db.Requests.Add(new InboxRequestEntity
            {
                PacketId = m.PacketId,
                SourceNode = m.SourceNode,
                SourceIp = remoteIp ?? m.SourceIp,
                FileName = PackageNaming.FileName(m),
                AlgorithmCode = m.AlgorithmCode,
                OperationName = m.OperationName,
                ValidationResult = package.SenderPinned ? ValidationLabels.SignatureOk : ValidationLabels.Unconfirmed,
                Status = RequestStates.Pending,
                StoragePath = path,
                ManifestJson = JsonSerializer.Serialize(m, ProtocolJson.Options),
                ReceivedUtc = now.UtcDateTime,
            });
            await db.SaveChangesAsync(ct);
        }

        await audit.LogAsync("inbox.received", m.SourceNode, null, $"{m.AlgorithmCode} {m.PacketId}", ct);
        hub.Publish(new Notifications.NodeEvent(Notifications.NodeEventKind.InboxReceived,
            $"Nueva solicitud de {m.SourceNode}: {m.AlgorithmCode} ({m.OperationName})", now, m.SourceNode));
        return new ReceiveResponse(m.PacketId, RequestStates.Pending, Identifiers.FormatTimestamp(now));
    }

    public async Task<IReadOnlyList<InboxRequestEntity>> ListAsync(CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        return await db.Requests.AsNoTracking().OrderByDescending(r => r.ReceivedUtc).ToListAsync(ct);
    }

    /// <summary>Aceptar: inserta en Consultas con origen <c>Recibido</c>.</summary>
    public async Task<PackageEntity> AcceptAsync(int requestId, CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var r = await db.Requests.FirstOrDefaultAsync(x => x.Id == requestId, ct)
            ?? throw new InvalidOperationException("Solicitud no encontrada.");
        if (r.Status != RequestStates.Pending || r.StoragePath is null || r.ManifestJson is null)
        {
            throw new InvalidOperationException("Solo se pueden aceptar solicitudes pendientes con paquete.");
        }

        var zip = await node.Store.ReadAsync(r.StoragePath, ct);
        var manifest = JsonSerializer.Deserialize<Manifest>(r.ManifestJson, ProtocolJson.Options)!;
        var stored = await library.SaveAsync(zip, r.FileName, manifest, PackageOrigins.Received, ct);
        node.Store.Delete(r.StoragePath);
        r.Status = RequestStates.Accepted;
        r.StoragePath = null;
        r.PackageId = stored.Id;
        r.DecidedUtc = node.Clock.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(ct);
        await audit.LogAsync("inbox.accepted", r.SourceNode, null, r.PacketId, ct);
        return stored;
    }

    /// <summary>Rechazar: estado <c>Rechazada</c>; el zip se descarta.</summary>
    public async Task RejectAsync(int requestId, CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var r = await db.Requests.FirstOrDefaultAsync(x => x.Id == requestId, ct)
            ?? throw new InvalidOperationException("Solicitud no encontrada.");
        if (r.Status != RequestStates.Pending)
        {
            throw new InvalidOperationException("Solo se pueden rechazar solicitudes pendientes.");
        }

        if (r.StoragePath is not null)
        {
            node.Store.Delete(r.StoragePath);
        }

        r.Status = RequestStates.Rejected;
        r.StoragePath = null;
        r.DecidedUtc = node.Clock.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(ct);
        await audit.LogAsync("inbox.rejected.user", r.SourceNode, null, r.PacketId, ct);
    }

    /// <summary>
    /// Paquetes con manifiesto legible pero integridad, certificado o firma inválidos se registran como
    /// <c>Inválida</c>/<c>Rechazada</c> (sin guardar el zip) para que el usuario los vea en Solicitudes.
    /// </summary>
    private async Task RecordInvalidAsync(byte[] zip, string? remoteIp, ProtocolException error, CancellationToken ct)
    {
        if (ErrorCodes.Get(error.Code).HttpStatus != 422)
        {
            return;
        }

        Manifest m;
        try
        {
            using var archive = ZipSafety.Open(zip);
            m = PackageValidator.ParseManifest(ZipSafety.ReadAll(archive.GetEntry(ProtocolConstants.EntryManifest)!));
        }
        catch (ProtocolException)
        {
            return;
        }

        await using var db = await dbf.CreateDbContextAsync(ct);
        db.Requests.Add(new InboxRequestEntity
        {
            PacketId = m.PacketId,
            SourceNode = m.SourceNode,
            SourceIp = remoteIp ?? m.SourceIp,
            FileName = PackageNaming.FileName(m),
            AlgorithmCode = m.AlgorithmCode,
            OperationName = m.OperationName,
            ValidationResult = ValidationLabels.Invalid,
            Status = RequestStates.Rejected,
            ErrorCode = error.Code,
            ReceivedUtc = node.Clock.GetUtcNow().UtcDateTime,
            DecidedUtc = node.Clock.GetUtcNow().UtcDateTime,
        });
        await db.SaveChangesAsync(ct);
    }
}
