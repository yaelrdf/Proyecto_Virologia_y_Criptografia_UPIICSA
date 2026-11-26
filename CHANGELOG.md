# Registro de cambios

Todos los cambios relevantes del nodo EQ08 se documentan aquí. El formato sigue [Keep a Changelog 1.1.0](https://keepachangelog.com/es-ES/1.1.0/) y el proyecto usa [versionado semántico](https://semver.org/lang/es/).

## [Sin publicar]

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
