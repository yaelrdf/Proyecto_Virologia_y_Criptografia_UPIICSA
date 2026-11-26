# CLAUDE.md — Nodo EQ08 · Centro de Ciberseguridad Comunitario

Reglas permanentes para cualquier sesión de Claude Code en este repositorio. Léelas antes de trabajar.

## Qué es este proyecto

Nodo **`EQ08`** (Equipo 8) del Centro de Ciberseguridad Comunitario (Virología y Criptografía, UPIICSA 2027-1). Es una aplicación .NET que:

- Ejecuta localmente los algoritmos **`HASHSHA`** (SHA-256, SHA-512) y **`HMACSHA256`** (HMAC-SHA256).
- Delega los otros 19 algoritmos de la lista oficial a los nodos de los demás equipos por API.
- Envía y recibe paquetes `.zip` firmados (RSA-PSS) con certificado X.509 autofirmado.
- Ofrece una interfaz web (Blazor) en español.

## Fuentes de verdad (en este orden)

1. `docs/estandar/Estandar_Comunicacion_v2.0.md`: **normativo**. Todo lo que viaja por la red (identificadores, puertos, manifiesto, firma, sobres, endpoints, errores, validaciones) DEBE cumplirlo al pie de la letra. Si el código y el estándar difieren, gana el estándar.
2. `docs/plan/Plan_Implementacion_EQ08.md`: decisiones del equipo, arquitectura, fases y criterios de aceptación.
3. `docs/referencia/`: requerimientos originales del curso, lista de algoritmos, asignación por equipo y estándar v1.0 (solo histórico, **no implementar v1.0**).

Si encuentras una ambigüedad en el estándar, NO la resuelvas con una suposición silenciosa: documenta la interpretación en `docs/arquitectura/decisiones/` (ADR) y en la sección de pendientes del backlog.

## Stack fijo

| Tema | Valor |
| --- | --- |
| Runtime | **.NET 10 LTS** (`net10.0`). No usar .NET 8/9 (fuera de soporte) |
| Web | ASP.NET Core + **Blazor Web App** con interactividad **Server** |
| Datos | EF Core 10 + **SQLite** (`Microsoft.EntityFrameworkCore.Sqlite`) |
| Pruebas | xUnit + FluentAssertions (o `Shouldly`) + bUnit para componentes + `WebApplicationFactory` para la API |
| Cripto | Solo `System.Security.Cryptography` (sin BouncyCastle salvo justificación en ADR) |
| Plataformas | Desarrollo en Linux; ejecución en **Windows y Linux** (`win-x64`, `linux-x64`) |
| Licencia | GPL-3.0 (archivo `LICENSE`; no modificar) |

## Estructura de la solución

```text
CentroCiber.slnx
Directory.Build.props          # net10.0, Nullable, ImplicitUsings, TreatWarningsAsErrors, AnalysisLevel latest
Directory.Packages.props       # Central Package Management
.config/dotnet-tools.json      # dotnet-ef como herramienta local (dotnet tool restore)
src/
  CentroCiber.Web/             # Host: Blazor, controladores API, Kestrel 5008/5108, filtro solo-LAN
  CentroCiber.Application/     # Casos de uso, IAlgorithmProvider, proveedores local/remoto, trabajos
  CentroCiber.Crypto/          # HASHSHA, HMACSHA256, identidad X.509/PFX, RSA-PSS, CC-ENV-1
  CentroCiber.Packaging/       # Manifiesto v2.0, hash canónico, cadena de firma, zip, 14 validaciones
  CentroCiber.Discovery/       # Anuncio/oyente UDP 5099, escaneo, directorio, TOFU
  CentroCiber.Infrastructure/  # EF Core + SQLite, HttpClient a otros nodos, almacenamiento de zips
tests/
  CentroCiber.Crypto.Tests/
  CentroCiber.Packaging.Tests/
  CentroCiber.Api.Tests/       # WebApplicationFactory + nodo simulado (MockNode)
  CentroCiber.Web.Tests/       # bUnit
  interop/                     # scripts Python (cryptography) que verifican firmas/sobres de EQ08
vectores/EQ08/                 # Vectores de prueba públicos (sección 16.1 del estándar)
scripts/                       # cloud-setup.sh, firewall, publicación, dos nodos locales
docs/                          # estándar, plan, manuales, API, BD, backlog, ADRs
```

Dependencias permitidas entre proyectos: `Web → Application → (Crypto, Packaging, Discovery, Infrastructure)`; `Packaging → Crypto`; `Crypto` no depende de nadie.

## Comandos

```bash
dotnet tool restore                         # dotnet-ef local
dotnet restore CentroCiber.slnx
dotnet build CentroCiber.slnx -warnaserror
dotnet test CentroCiber.slnx                # debe pasar SIEMPRE antes de cada commit
dotnet run --project src/CentroCiber.Web    # http://0.0.0.0:5008 y https://0.0.0.0:5108
dotnet tool run dotnet-ef migrations add <Nombre> -p src/CentroCiber.Infrastructure -s src/CentroCiber.Web
dotnet publish src/CentroCiber.Web -c Release -r linux-x64 --self-contained
dotnet publish src/CentroCiber.Web -c Release -r win-x64   --self-contained
python3 tests/interop/verify_package.py <zip>   # verificación independiente
```

Si .NET no está instalado en un entorno nuevo: `sudo bash scripts/cloud-setup.sh`.

## Convenciones

- **Idioma:** documentación, interfaz, mensajes al usuario y `detail` de errores en **español**. Código, identificadores, nombres de archivos de código, comentarios técnicos y **mensajes de commit en inglés**. Los campos JSON del protocolo son los del estándar (inglés, `camelCase`).
- **Commits:** Conventional Commits (`feat(crypto): add CC-ENV-1 envelope`). Un commit por historia del backlog; al cerrar una fase, un commit `chore(phase-N): close phase N` que actualice backlog y CHANGELOG.
- **Ramas:** una sola rama de trabajo para todo el desarrollo; no abrir PRs intermedios.
- **Estilo:** `.editorconfig` del repo; `dotnet format` antes de commit; archivos con `namespace` de archivo; `async` de punta a punta con `CancellationToken`.
- **Nombres del protocolo:** usa constantes centralizadas (`ProtocolConstants`) para puertos, códigos de algoritmo, nombres de archivo del zip, códigos `E-...`. Nunca literales sueltos.

## Reglas de seguridad (no negociables)

- Nunca hacer commit de llaves privadas reales, `.pfx`, contraseñas, bases de datos (`*.db`) ni zips recibidos. Solo `vectores/EQ08/` contiene una llave marcada **`PRUEBA`** generada para ese fin.
- La contraseña del PFX se lee de `CC_PFX_PASSWORD` (o *user-secrets* en desarrollo). Nunca de `appsettings*.json`.
- Secretos (claves HMAC, sobres abiertos) nunca en logs, URLs, encabezados, BD ni `manifest.json`. Borrar buffers con `CryptographicOperations.ZeroMemory` al terminar.
- Comparaciones de hash/MAC/firma con `CryptographicOperations.FixedTimeEquals`.
- Extraer zips solo en memoria o en carpeta temporal tras validar nombres, número de entradas, tamaño descomprimido (≤ 200 MB) y razón de compresión (≤ 100:1).
- La interfaz web solo responde a IPs privadas/loopback; la API sí responde a toda la LAN.

## Detalles técnicos de .NET 10 a respetar

- Hash: `SHA256.HashData`, `SHA512.HashData`; HMAC: `HMACSHA256.HashData`.
- Firma: `rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)` (en .NET la sal PSS = 32 bytes con SHA-256, lo que pide el estándar).
- Sobre `CC-ENV-1`: `RSAEncryptionPadding.OaepSHA256` + `AesGcm` (nonce 12, tag 16, AAD = UTF-8 del `requestId`/`packetId`).
- Certificado: `CertificateRequest(..., RSASignaturePadding.Pkcs1)` + `CreateSelfSigned`; cargar PFX con `X509CertificateLoader.LoadPkcs12FromFile` (el constructor de `X509Certificate2` está obsoleto).
- Huella: `SHA256.HashData(cert.RawData)` → hex MAYÚSCULAS.
- UDP: `UdpClient` con `EnableBroadcast = true` y `SocketOptionName.ReuseAddress` para poder correr varios nodos en una sola máquina (Linux y Windows).
- Kestrel: `ListenAnyIP(5008)` y `ListenAnyIP(5108, o => o.UseHttps(cert))`; puertos configurables por `appsettings` para pruebas.
- Rutas de archivo siempre con `Path.Combine`; nada de `\` ni `/` literales.

## Pruebas y verificación

- Cada regla “DEBE” del estándar que EQ08 implementa tiene al menos una prueba que la nombra (`// Estándar §13.1 #8`).
- Cada código `E-...` que EQ08 puede devolver tiene una prueba de API.
- Interoperabilidad: los paquetes y sobres de EQ08 se verifican con un script Python independiente (`tests/interop/`) en la suite.
- El nodo simulado (`MockNode`) imita a otro equipo (p. ej. `EQ01`/`AESGCM`) para probar la delegación sin red real.
- No declares una fase terminada si `dotnet build -warnaserror` o `dotnet test` fallan. No inventes resultados de pruebas.
- Este entorno de nube no tiene Windows ni una LAN real: las pruebas de Windows las corre la CI (`windows-latest`) y el equipo; el descubrimiento UDP se prueba con dos instancias en loopback.

## Documentación obligatoria

Mantener al día, en español: `README.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `CHANGELOG.md`, `docs/manuales/` (técnico, instalación y configuración, identidad, reporte general), `docs/backlog/Backlog.md`, `docs/api/` (OpenAPI), `docs/base-de-datos/`, `docs/arquitectura/` (incl. ADRs), `docs/interoperabilidad/`. Cuando cambie el comportamiento, actualiza la documentación en el mismo commit.
