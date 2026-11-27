# Semilla de la base de datos

La semilla se define en `src/CentroCiber.Infrastructure/Data/SeedData.cs` con `HasData` y se aplica en la migración inicial. Suma **38 registros**; el requerimiento del curso es ≥ 30. La prueba `Database_is_seeded_with_at_least_30_records` de `tests/CentroCiber.Api.Tests` lo verifica.

| Tabla | Registros | Contenido |
| --- | ---: | --- |
| `Algorithms` | 21 | Los 21 algoritmos de la tabla 4.1 del estándar, con dueño, nombres de operación y tipo de llave |
| `Teams` | 8 | Equipos 1–8 con `nodeId`, puertos calculados y algoritmos asignados |
| `Nodes` | 1 | El propio nodo EQ08 (`IsSelf`); al arrancar se actualizan su IP, puertos y huella |
| `Packages` | 4 | Ejemplos de Consultas: un HASHSHA y un HMACSHA256 generados, un AESGCM recibido de EQ01 y un resultado HASHSHA válido |
| `Requests` | 3 | Ejemplos de Solicitudes: Pendiente / «Firma OK» (EQ01), Aceptada / «Remitente no confirmado» (EQ05) y Rechazada / «Inválida» con `E-SIGNATURE` (EQ03) |
| `Settings` | 1 | Variantes SHA-256, SHA-512 y HMAC-SHA256; HTTPS y bandeja activos; 50 MB |
| **Total** | **38** | |

Los registros de ejemplo de `Packages` y `Requests` tienen `IsSample = 1`: la interfaz los marca como «ejemplo» y no ofrece descargarlos ni aceptarlos, porque no tienen zip en disco. Los registros reales se agregan con el uso: intercambios con otros nodos, delegaciones y bitácora.

> Pendiente del plan §7: confirmar con el docente si los 30 registros pueden ser semilla o si deben provenir de intercambios reales. Si se requieren reales, la [matriz de interoperabilidad](../interoperabilidad/Matriz.md) de la prueba integrada los genera en `Packages`, `Requests`, `RemoteOperations` y `AuditLog`.
