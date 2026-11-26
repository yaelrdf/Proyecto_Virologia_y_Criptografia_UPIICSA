using System.Text.Json;
using CentroCiber.Crypto.Envelope;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Infrastructure.Data;
using CentroCiber.Infrastructure.Data.Entities;
using CentroCiber.Packaging;
using Microsoft.EntityFrameworkCore;

namespace CentroCiber.Application.Services;

/// <summary>Consultas (§15): paquetes generados, recibidos y resultados.</summary>
public sealed class PackageLibrary(
    IDbContextFactory<CentroCiberDbContext> dbf,
    NodeContext node,
    PackageValidator validator,
    Notifications.NotificationHub hub)
{
    public const string FolderPackages = "consultas";

    public async Task<PackageEntity> SaveAsync(byte[] zip, string fileName, Manifest manifest, string origin, CancellationToken ct)
    {
        var path = await node.Store.SaveAsync(FolderPackages, manifest.PacketId, zip, ct);
        await using var db = await dbf.CreateDbContextAsync(ct);
        var entity = new PackageEntity
        {
            PacketId = manifest.PacketId,
            FileName = fileName,
            Origin = origin,
            PacketType = manifest.PacketType,
            AlgorithmCode = manifest.AlgorithmCode,
            Operation = manifest.Operation,
            SourceNode = manifest.SourceNode,
            ProducerNode = manifest.ProducerNode,
            RequestId = manifest.RequestId,
            EncryptedSha256 = manifest.EncryptedSha256,
            KeyId = manifest.KeyRef?.KeyId,
            KeyOwnerNode = manifest.KeyRef?.OwnerNode,
            OriginalFileName = manifest.OriginalFileName,
            StoragePath = path,
            SizeBytes = zip.LongLength,
            ManifestJson = JsonSerializer.Serialize(manifest, ProtocolJson.Options),
            VerificationValid = manifest.Verification?.Valid,
            VerificationDetail = manifest.Verification?.Detail,
            CreatedUtc = node.Clock.GetUtcNow().UtcDateTime,
        };
        db.Packages.Add(entity);
        await db.SaveChangesAsync(ct);
        hub.Publish(new Notifications.NodeEvent(Notifications.NodeEventKind.PackageStored,
            $"{origin}: {fileName}", node.Clock.GetUtcNow(), manifest.SourceNode));
        return entity;
    }

    public async Task<IReadOnlyList<PackageEntity>> ListAsync(string? origin = null, CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var q = db.Packages.AsNoTracking();
        if (!string.IsNullOrEmpty(origin))
        {
            q = q.Where(p => p.Origin == origin);
        }

        return await q.OrderByDescending(p => p.CreatedUtc).ToListAsync(ct);
    }

    public async Task<PackageEntity?> GetAsync(int id, CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        return await db.Packages.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, ct);
    }

    public async Task<byte[]> ReadZipAsync(PackageEntity entity, CancellationToken ct = default) =>
        entity.StoragePath is null
            ? throw new ProtocolException(ErrorCodes.Request, "Este registro es de ejemplo y no tiene zip en disco.")
            : await node.Store.ReadAsync(entity.StoragePath, ct);

    /// <summary>Abre el <c>resultEnvelope</c> de un <c>result</c> dirigido a este nodo y devuelve el original.</summary>
    public async Task<byte[]> OpenResultAsync(byte[] resultZip, CancellationToken ct = default)
    {
        var validated = await validator.ValidateAsync(resultZip,
            PackageValidationOptions.ForInverse with { ExpectedPacketType = ProtocolConstants.PacketTypeResult }, ct);
        var envelope = validated.Manifest.ResultEnvelope
            ?? throw new ProtocolException(ErrorCodes.Manifest, "El resultado no trae resultEnvelope.");
        return EnvelopeCrypto.OpenDetached(envelope, validated.Data, node.Identity, validated.Manifest.PacketId);
    }

    /// <summary>Valida un paquete antes de guardarlo (sin ventana de tiempo ni anti-repetición).</summary>
    public Task<ValidatedPackage> ValidateForStorageAsync(byte[] zip, CancellationToken ct = default) =>
        validator.ValidateAsync(zip, PackageValidationOptions.ForInverse with { ExpectedPacketType = null }, ct);

    public async Task DeleteAsync(int id, CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var entity = await db.Packages.FirstOrDefaultAsync(p => p.Id == id, ct);
        if (entity is null)
        {
            return;
        }

        if (entity.StoragePath is not null)
        {
            node.Store.Delete(entity.StoragePath);
        }

        db.Packages.Remove(entity);
        await db.SaveChangesAsync(ct);
    }
}
