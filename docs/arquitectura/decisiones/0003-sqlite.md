# ADR 0003 — SQLite con EF Core

- **Estado:** Aceptada (plan §3.3)
- **Fecha:** 2026-11-26

## Contexto

El curso pide una base de datos con al menos 30 registros. El nodo es de un solo usuario y debe instalarse en Windows y Linux sin servicios externos.

## Decisión

Usar **EF Core 10 + SQLite** (`Microsoft.EntityFrameworkCore.Sqlite`), con migraciones versionadas en `src/CentroCiber.Infrastructure/Data/Migrations` y una semilla de 38 registros (`SeedData`). La base se crea y migra al arrancar. Los zips viven en disco (`data/paquetes`); la BD guarda la ruta y los hashes.

## Consecuencias

- Un archivo `data/centrociber.db` por nodo; ignorado por git.
- `DateTime` en UTC (SQLite no ordena `DateTimeOffset`).
- Para varios nodos en una sola máquina, cada uno usa su propia carpeta de datos (`CC_Node__DataPath`).
