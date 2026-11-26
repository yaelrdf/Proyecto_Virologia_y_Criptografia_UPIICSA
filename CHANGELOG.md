# Registro de cambios

Todos los cambios relevantes del nodo EQ08 se documentan aquí. El formato sigue [Keep a Changelog 1.1.0](https://keepachangelog.com/es-ES/1.1.0/) y el proyecto usa [versionado semántico](https://semver.org/lang/es/).

## [Sin publicar]

### Fase 4 — Paquetes v2.0

#### Agregado

- Constructor de paquetes `package` y `result` con manifiesto v2.0 completo, firma de la cadena §8.4 y nomenclatura `EQ08_...` / `RES_EQ08_...` (§9.2).
- Contenido `multipart` con zip interno `part-NN.bin` y arreglo `parts` (§9.4).
- Reenvío con re-firma (§9.6).
- Validador con las 14 comprobaciones de §13.1 en orden, más `E-CERT-UNTRUSTED` para remitentes fijados, con reporte paso a paso para la interfaz. Hay una prueba por cada código (incluye zip-slip, zip-bomb, 4 archivos, timestamp viejo y futuro, y `packetId` repetido).
- Los datos de `datos.enc` y `resultado.enc` se guardan sin comprimir para que nunca superen la razón 100:1.
- Paquetes `package`, `result` y `multipart` de .NET verificados por Python.

### Fase 3 — Algoritmos propios

#### Agregado

- `HASHSHA` con SHA-256 y SHA-512, y `HMACSHA256` con clave ≥ 32 bytes; las comparaciones de `inverse` usan `CryptographicOperations.FixedTimeEquals` y las claves se borran de memoria.
- Contrato `IAlgorithmProvider` (`forward`/`inverse`) común a algoritmos locales y remotos.
- Vectores NIST FIPS 180-4 y RFC 4231 (casos 1–7) en las pruebas.

### Fase 2 — Identidad y primitivas

#### Agregado

- Identidad X.509 del nodo (§7): RSA-2048 autofirmado, `CN=EQ08, OU=Equipo 08, O=Centro de Ciberseguridad, C=MX`, 365 días, serie aleatoria de 72 bits, usos `digitalSignature` y `keyEncipherment`, guardada en PFX protegido por `CC_PFX_PASSWORD`.
- Firma RSA-PSS-SHA256 con sal de 32 bytes (§8.2), sobre híbrido `CC-ENV-1` (§8.3), hash canónico de `publicParameters` (§8.5) y cadena de firma (§8.4).
- Implementación independiente en Python (`tests/interop/`) que verifica lo producido por .NET y crea sobres que .NET abre, integrada en `dotnet test` y en la CI.

### Fase 1 — Base multiplataforma

#### Agregado

- Solución `CentroCiber.slnx` (.NET 10) con los proyectos `Web`, `Application`, `Crypto`, `Packaging`, `Discovery` e `Infrastructure`, pruebas y herramientas.
- `Directory.Build.props` (advertencias como errores, analizadores `latest`), administración central de paquetes y `dotnet-ef` como herramienta local.
- Constantes del protocolo, validadores de identificadores (§3), catálogo de errores (Anexo B) y diccionario oficial de algoritmos (§4.1).
- Modelo EF Core + SQLite con migración inicial y semilla de 38 registros.
- Configuración por `appsettings.json` y variables de entorno con prefijo `CC_`.
- Host Kestrel en `5000 + teamNumber` con `GET /api/status` mínimo.
- CI en Ubuntu y Windows, y publicación autocontenida `win-x64` y `linux-x64`.

#### Cambiado

- `.gitignore` ampliado para PFX, bases de datos, datos, secretos y `.env`.
