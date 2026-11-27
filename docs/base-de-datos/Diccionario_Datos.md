# Diccionario de datos

Todas las fechas se guardan como `DateTime` en **UTC**. Los textos son `TEXT` en SQLite. «Req.» indica que el campo es obligatorio (`NOT NULL`).

## Algorithms — diccionario 4.1 del estándar

| Columna | Tipo | Req. | Descripción |
| --- | --- | :---: | --- |
| `Id` | INTEGER PK | ✔ | `algorithmId` oficial (1–21), sin autoincremento |
| `Code` | TEXT único | ✔ | `algorithmCode` (`HASHSHA`, `AESGCM`, …) |
| `Name` | TEXT | ✔ | Nombre descriptivo |
| `Category` | TEXT | ✔ | Categoría (Integridad, Simétrico…) |
| `OwnerTeam` | INTEGER | | Equipo dueño; nulo = reservado (17–21) |
| `ForwardName` / `InverseName` | TEXT | ✔ | Significado de `forward`/`inverse` (§4.3) |
| `KeyKind` | TEXT | ✔ | `None`, `Secret`, `OptionalSecret`, `KeyId` |

## Teams — equipos del Centro

| Columna | Tipo | Req. | Descripción |
| --- | --- | :---: | --- |
| `TeamNumber` | INTEGER PK | ✔ | 1–8 |
| `NodeId` | TEXT único | ✔ | `EQ01` … `EQ08` |
| `HttpPort` / `HttpsPort` | INTEGER | ✔ | 5000+n / 5100+n |
| `AlgorithmCodes` | TEXT | ✔ | Códigos asignados, separados por coma |

## Nodes — directorio local (§6.4)

| Columna | Tipo | Req. | Descripción |
| --- | --- | :---: | --- |
| `Id` | INTEGER PK | ✔ | Autoincremento |
| `NodeId` | TEXT único | ✔ | Identidad del nodo |
| `TeamNumber` | INTEGER | ✔ | Número de equipo |
| `Ip`, `HttpPort`, `HttpsPort` | TEXT / INTEGER | ✔ / ✔ / | Ubicación actual; `HttpsPort` nulo si no ofrece HTTPS |
| `PinnedThumbprintSha256` | TEXT | | Huella **confirmada** por el usuario (TOFU) |
| `ObservedThumbprintSha256` | TEXT | | Última huella verificada (status + certificate) |
| `CertificatePem` | TEXT | | Certificado público del nodo (para cifrar sobres hacia él) |
| `Algorithms` | TEXT | ✔ | Códigos que anuncia, separados por coma |
| `Source` | TEXT | ✔ | `beacon`, `scan`, `manual` o `request` |
| `Status` | TEXT | ✔ | `online` / `offline` |
| `TrustState` | TEXT | ✔ | `Propio`, `PendienteConfirmar`, `Confirmado`, `HuellaCambiada`, `Inválido` |
| `IsSelf` | INTEGER (bool) | ✔ | Fila del propio nodo |
| `LastSeenUtc` | TEXT (fecha) | | Último anuncio o respuesta |
| `ProfileJson` | TEXT | | Caché de `GET /api/algorithms` del nodo |
| `LastError` | TEXT | | Último error de verificación |

## Packages — Consultas (§15)

| Columna | Tipo | Req. | Descripción |
| --- | --- | :---: | --- |
| `Id` | INTEGER PK | ✔ | Autoincremento |
| `PacketId` | TEXT único | ✔ | `packetId` del manifiesto |
| `FileName` | TEXT | ✔ | Nombre según §9.2 |
| `Origin` | TEXT | ✔ | `Generado`, `Recibido` o `Resultado` |
| `PacketType` | TEXT | ✔ | `package` / `result` |
| `AlgorithmCode`, `Operation` | TEXT | ✔ | Algoritmo y operación |
| `SourceNode`, `ProducerNode` | TEXT | ✔ | Quien firmó y quien ejecutó |
| `RequestId` | TEXT | | Petición `/api/crypto/*` que lo originó |
| `EncryptedSha256` | TEXT | ✔ | SHA-256 de `datos.enc` / `resultado.enc` |
| `KeyId`, `KeyOwnerNode` | TEXT | | `keyRef` (§12), si aplica |
| `OriginalFileName` | TEXT | | Nombre del original |
| `StoragePath` | TEXT | | Ruta relativa del zip; nulo en registros de ejemplo |
| `SizeBytes` | INTEGER | ✔ | Tamaño del zip |
| `ManifestJson` | TEXT | ✔ | Manifiesto completo (no contiene secretos, §9.5) |
| `VerificationValid`, `VerificationDetail` | INTEGER / TEXT | | Veredicto de un `result` de hash/MAC |
| `IsSample` | INTEGER (bool) | ✔ | Registro de la semilla |
| `CreatedUtc` | TEXT (fecha) | ✔ | Fecha de alta |

## Requests — bandeja de Solicitudes (§15)

| Columna | Tipo | Req. | Descripción |
| --- | --- | :---: | --- |
| `Id` | INTEGER PK | ✔ | Autoincremento |
| `PacketId` | TEXT | ✔ | `packetId` recibido |
| `SourceNode`, `SourceIp` | TEXT | ✔ | Remitente e IP de origen |
| `FileName` | TEXT | ✔ | Nombre según §9.2 (calculado del manifiesto) |
| `AlgorithmCode`, `OperationName` | TEXT | ✔ | Algoritmo y operación |
| `ValidationResult` | TEXT | ✔ | `Firma OK`, `Inválida` o `Remitente no confirmado` |
| `Status` | TEXT | ✔ | `Pendiente`, `Aceptada` o `Rechazada` |
| `ErrorCode` | TEXT | | Código `E-...` si se rechazó por validación |
| `StoragePath` | TEXT | | Zip mientras está pendiente |
| `ManifestJson` | TEXT | | Manifiesto |
| `PackageId` | INTEGER | | Registro de Consultas tras aceptar |
| `IsSample` | INTEGER (bool) | ✔ | Registro de la semilla |
| `ReceivedUtc`, `DecidedUtc` | TEXT (fecha) | ✔ / | Recepción y decisión |

## RemoteOperations — peticiones `/api/crypto/*`

| Columna | Tipo | Req. | Descripción |
| --- | --- | :---: | --- |
| `Id` | INTEGER PK | ✔ | Autoincremento |
| `RequestId` | TEXT (índice) | ✔ | `requestId` |
| `Direction` | TEXT | ✔ | `Saliente` (EQ08 delega) o `Entrante` (otro nodo pide a EQ08) |
| `PeerNode` | TEXT | ✔ | El otro nodo |
| `AlgorithmCode`, `Operation` | TEXT | ✔ | Algoritmo y operación |
| `JobId` | TEXT (índice) | | `jobId` si hubo `202` |
| `State` | TEXT | ✔ | `queued`, `running`, `done`, `failed` |
| `ErrorCode`, `ErrorDetail` | TEXT | | Error, si lo hubo |
| `ResultPackageId` | INTEGER | | Paquete resultante |
| `CreatedUtc`, `UpdatedUtc` | TEXT (fecha) | ✔ | Marcas de tiempo |

## SeenIds — anti-repetición (§13.1 #14, §13.2 #5)

| Columna | Tipo | Req. | Descripción |
| --- | --- | :---: | --- |
| `Id` | TEXT PK | ✔ | `packet:<uuid>` o `request:<uuid>` |
| `Kind` | TEXT | ✔ | `packet` / `request` |
| `SeenUtc` | TEXT (fecha) | ✔ | Primera vez visto |

## Settings — ajustes (una fila)

| Columna | Tipo | Req. | Descripción |
| --- | --- | :---: | --- |
| `Id` | INTEGER PK | ✔ | Siempre 1 |
| `EnabledVariants` | TEXT | ✔ | `SHA-256,SHA-512,HMAC-SHA256` |
| `HttpsEnabled` | INTEGER (bool) | ✔ | Ofrecer HTTPS (requiere reinicio) |
| `AcceptingPackages` | INTEGER (bool) | ✔ | Si es falso, la bandeja responde `E-BUSY` |
| `AutoAcceptInbox` | INTEGER (bool) | ✔ | Panel de pruebas: aceptar automáticamente los paquetes válidos (por omisión 0) |
| `MaxPayloadBytes` | INTEGER | ✔ | 52 428 800 |
| `PfxFileName` | TEXT | ✔ | Nombre del PFX (la contraseña nunca se guarda) |

## AuditLog — bitácora sin secretos

| Columna | Tipo | Req. | Descripción |
| --- | --- | :---: | --- |
| `Id` | INTEGER PK | ✔ | Autoincremento |
| `TimestampUtc` | TEXT (fecha, índice) | ✔ | Momento del evento |
| `Event` | TEXT | ✔ | `inbox.received`, `api.rejected`, `crypto.forward`, `delegate.inverse`, `delegate.error`, `outbox.sent`, `identity.regenerated`, … |
| `NodeId` | TEXT | | Nodo involucrado |
| `Code` | TEXT | | Código `E-...` |
| `Detail` | TEXT (≤ 500) | | Algoritmo e identificadores; **nunca** claves ni contenido |
