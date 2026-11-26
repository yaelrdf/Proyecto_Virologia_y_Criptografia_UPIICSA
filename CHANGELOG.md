# Registro de cambios

Todos los cambios relevantes del nodo EQ08 se documentan aquí. El formato sigue [Keep a Changelog 1.1.0](https://keepachangelog.com/es-ES/1.1.0/) y el proyecto usa [versionado semántico](https://semver.org/lang/es/).

## [Sin publicar]

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
