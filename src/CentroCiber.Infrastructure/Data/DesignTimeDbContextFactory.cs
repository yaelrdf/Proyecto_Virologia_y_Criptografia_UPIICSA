using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace CentroCiber.Infrastructure.Data;

/// <summary>Fábrica para <c>dotnet ef</c>: evita arrancar el host (y pedir la contraseña del PFX).</summary>
public sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<CentroCiberDbContext>
{
    public CentroCiberDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<CentroCiberDbContext>()
            .UseSqlite("Data Source=design-time.db")
            .Options;
        return new CentroCiberDbContext(options);
    }
}
