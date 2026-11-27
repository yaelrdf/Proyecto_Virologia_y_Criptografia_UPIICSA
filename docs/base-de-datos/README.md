# Base de datos del nodo EQ08

| Campo | Valor |
| --- | --- |
| Motor | SQLite 3 mediante EF Core 10 (`Microsoft.EntityFrameworkCore.Sqlite`) ([ADR 0003](../arquitectura/decisiones/0003-sqlite.md)) |
| Archivo | `data/centrociber.db` (configurable con `CC_Node__DataPath` / `CC_Node__DatabaseFileName`) |
| Esquema | `src/CentroCiber.Infrastructure/Data/CentroCiberDbContext.cs` |
| Migraciones | `src/CentroCiber.Infrastructure/Data/Migrations/` (`InitialCreate`, `AddAutoAcceptInbox`), aplicadas al arrancar |
| Semilla | `src/CentroCiber.Infrastructure/Data/SeedData.cs`: **38 registros** (mínimo del curso: 30) |

Documentos:

- [Diagrama entidad-relación](Diagrama_ER.md)
- [Diccionario de datos](Diccionario_Datos.md)
- [Semilla](Semilla.md)

Los zips **no** se guardan en la base de datos: viven en `data/paquetes/` y la BD guarda la ruta relativa y los hashes. Los secretos (claves HMAC, sobres abiertos) **nunca** se guardan.

## Consultas útiles

```bash
sqlite3 data/centrociber.db "SELECT NodeId, Status, TrustState, Ip, HttpPort FROM Nodes;"
```

```bash
sqlite3 data/centrociber.db "SELECT Origin, COUNT(*) FROM Packages GROUP BY Origin;"
```

```bash
sqlite3 data/centrociber.db "SELECT TimestampUtc, Event, NodeId, Code FROM AuditLog ORDER BY Id DESC LIMIT 20;"
```

## Agregar una migración

```bash
dotnet tool restore
dotnet tool run dotnet-ef migrations add <Nombre> -p src/CentroCiber.Infrastructure -s src/CentroCiber.Infrastructure -o Data/Migrations
```

Se usa `DesignTimeDbContextFactory`, así que no hace falta la contraseña del PFX para generar migraciones.
