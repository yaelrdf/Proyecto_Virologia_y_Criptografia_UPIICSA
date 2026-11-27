# Registro de decisiones de arquitectura (ADR)

Cada decisión importante, o cada interpretación de algo ambiguo en el estándar v2.0, se registra aquí. Los ADR marcados **Propuesta** son interpretaciones que el equipo debe aprobar y, de ser posible, proponer al coordinador del estándar.

| ADR | Título | Estado |
| --- | --- | --- |
| [0001](0001-dotnet-10.md) | .NET 10 LTS como plataforma | Aceptada |
| [0002](0002-blazor-server.md) | Blazor Web App con interactividad Server | Aceptada |
| [0003](0003-sqlite.md) | SQLite con EF Core | Aceptada |
| [0004](0004-pfx-password-env.md) | Contraseña del PFX en variable de entorno | Aceptada |
| [0005](0005-inverse-timestamp-replay.md) | En `inverse`, las reglas #13 y #14 se aplican a la petición | **Propuesta** |
| [0006](0006-unpinned-requester.md) | Peticiones de un solicitante sin huella fijada | **Propuesta** |
| [0007](0007-result-public-parameters.md) | `publicParameters` de un paquete `result` | **Propuesta** |
| [0008](0008-verify-failed.md) | `valid: false` se devuelve con 200 | Aceptada |
| [0009](0009-discovery-loopback.md) | Descubrimiento configurable para pruebas en una sola máquina | Aceptada |
| [0010](0010-protocol-constants-location.md) | Ubicación de constantes y contratos | Aceptada |
| [0011](0011-job-result-access.md) | Acceso al resultado de un trabajo y destino incorrecto | **Propuesta** |
| [0012](0012-certificate-notbefore.md) | `NotBefore` del certificado adelantado 10 minutos | Aceptada |
| [0013](0013-hmac-variants.md) | Variantes y parámetros estrictos de HASHSHA y HMACSHA256 | Aceptada |
| [0014](0014-tolerant-nullable-fields.md) | Campos anulables ausentes en manifiestos de otros nodos | **Propuesta** |
