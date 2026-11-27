using CentroCiber.Infrastructure.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace CentroCiber.Infrastructure.Data;

/// <summary>Contexto EF Core sobre SQLite del nodo.</summary>
public class CentroCiberDbContext(DbContextOptions<CentroCiberDbContext> options) : DbContext(options)
{
    public DbSet<AlgorithmEntity> Algorithms => Set<AlgorithmEntity>();

    public DbSet<TeamEntity> Teams => Set<TeamEntity>();

    public DbSet<NodeEntity> Nodes => Set<NodeEntity>();

    public DbSet<PackageEntity> Packages => Set<PackageEntity>();

    public DbSet<InboxRequestEntity> Requests => Set<InboxRequestEntity>();

    public DbSet<RemoteOperationEntity> RemoteOperations => Set<RemoteOperationEntity>();

    public DbSet<SeenIdEntity> SeenIds => Set<SeenIdEntity>();

    public DbSet<SettingsEntity> Settings => Set<SettingsEntity>();

    public DbSet<AuditLogEntity> AuditLog => Set<AuditLogEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<AlgorithmEntity>(e =>
        {
            e.ToTable("Algorithms");
            e.Property(x => x.Id).ValueGeneratedNever();
            e.HasIndex(x => x.Code).IsUnique();
        });
        modelBuilder.Entity<TeamEntity>(e =>
        {
            e.ToTable("Teams");
            e.HasKey(x => x.TeamNumber);
            e.Property(x => x.TeamNumber).ValueGeneratedNever();
            e.HasIndex(x => x.NodeId).IsUnique();
        });
        modelBuilder.Entity<NodeEntity>(e =>
        {
            e.ToTable("Nodes");
            e.HasIndex(x => x.NodeId).IsUnique();
        });
        modelBuilder.Entity<PackageEntity>(e =>
        {
            e.ToTable("Packages");
            e.HasIndex(x => x.PacketId).IsUnique();
            e.HasIndex(x => x.Origin);
        });
        modelBuilder.Entity<InboxRequestEntity>(e =>
        {
            e.ToTable("Requests");
            e.HasIndex(x => x.Status);
        });
        modelBuilder.Entity<RemoteOperationEntity>(e =>
        {
            e.ToTable("RemoteOperations");
            e.HasIndex(x => x.RequestId);
            e.HasIndex(x => x.JobId);
        });
        modelBuilder.Entity<SeenIdEntity>(e => e.ToTable("SeenIds"));
        modelBuilder.Entity<SettingsEntity>(e =>
        {
            e.ToTable("Settings");
            e.Property(x => x.Id).ValueGeneratedNever();
        });
        modelBuilder.Entity<AuditLogEntity>(e =>
        {
            e.ToTable("AuditLog");
            e.HasIndex(x => x.TimestampUtc);
        });

        SeedData.Apply(modelBuilder);
    }
}
