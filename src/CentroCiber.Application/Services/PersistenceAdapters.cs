using CentroCiber.Infrastructure.Data;
using CentroCiber.Infrastructure.Data.Entities;
using CentroCiber.Packaging;
using Microsoft.EntityFrameworkCore;

namespace CentroCiber.Application.Services;

/// <summary>Anti-repetición sobre la tabla <c>SeenIds</c> (§13.1 #14, §13.2 #5).</summary>
public sealed class DbReplayGuard(IDbContextFactory<CentroCiberDbContext> dbf, TimeProvider clock) : IReplayGuard
{
    private static readonly SemaphoreSlim Gate = new(1, 1);

    public async Task<bool> HasSeenAsync(string kind, string id, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        return await db.SeenIds.AnyAsync(s => s.Id == kind + ":" + id, ct);
    }

    public async Task<bool> TryMarkSeenAsync(string kind, string id, CancellationToken ct)
    {
        await Gate.WaitAsync(ct);
        try
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            var key = kind + ":" + id;
            if (await db.SeenIds.AnyAsync(s => s.Id == key, ct))
            {
                return false;
            }

            db.SeenIds.Add(new SeenIdEntity { Id = key, Kind = kind, SeenUtc = clock.GetUtcNow().UtcDateTime });
            await db.SaveChangesAsync(ct);
            return true;
        }
        finally
        {
            Gate.Release();
        }
    }
}

/// <summary>Bitácora sin secretos (tabla <c>AuditLog</c>).</summary>
public sealed class AuditService(IDbContextFactory<CentroCiberDbContext> dbf, TimeProvider clock)
{
    public async Task LogAsync(string evt, string? nodeId, string? code, string? detail, CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        db.AuditLog.Add(new AuditLogEntity
        {
            TimestampUtc = clock.GetUtcNow().UtcDateTime,
            Event = evt,
            NodeId = nodeId,
            Code = code,
            Detail = detail is { Length: > 500 } ? detail[..500] : detail,
        });
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<AuditLogEntity>> RecentAsync(int count, CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        return await db.AuditLog.OrderByDescending(a => a.Id).Take(count).ToListAsync(ct);
    }
}

/// <summary>Ajustes persistidos (tabla <c>Settings</c>).</summary>
public sealed class SettingsService(IDbContextFactory<CentroCiberDbContext> dbf)
{
    public async Task<SettingsEntity> GetAsync(CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        return await db.Settings.AsNoTracking().SingleAsync(s => s.Id == 1, ct);
    }

    public async Task SaveAsync(SettingsEntity settings, CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        db.Settings.Update(settings);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlySet<string>> EnabledVariantsAsync(CancellationToken ct = default)
    {
        var s = await GetAsync(ct);
        return s.EnabledVariants.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet(StringComparer.Ordinal);
    }
}
