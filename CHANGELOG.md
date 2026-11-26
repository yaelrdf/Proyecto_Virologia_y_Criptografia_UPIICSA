# Registro de cambios

Todos los cambios relevantes del nodo EQ08 se documentan aquí. El formato sigue [Keep a Changelog 1.1.0](https://keepachangelog.com/es-ES/1.1.0/) y el proyecto usa [versionado semántico](https://semver.org/lang/es/).

## [Sin publicar]

### Fase 8 — Interfaz web

#### Agregado

- Identidad «Atalaya EQ08» (propuesta): logotipo SVG original, paleta con contraste AA verificado y hoja de estilos propia, sin dependencias externas.
- Pantallas en español: Operar (ida), Operar (vuelta) con validación paso a paso, Solicitudes, Consultas, Nodos y Ajustes.
- Formularios de parámetros generados desde el perfil `GET /api/algorithms` (propio, del dueño en caché o mínimo de la tabla 4.2), con botón «Generar clave».
- Barra de estado (nodo, IP, puertos, oyente UDP, huella) y notificaciones en tiempo real por el circuito de Blazor.
- Filtro solo-LAN para la interfaz; la API sigue abierta a la LAN.
- Descargas del zip y del original de un resultado (abierto con la llave propia).
- Pruebas bUnit de los componentes clave y pruebas de host de las 6 pantallas.

### Fase 7 — Cliente de delegación

#### Agregado

- Proveedor remoto para los 19 algoritmos ajenos: elige al dueño (tabla 4.1; para reservados, el `teamNumber` menor), exige huella fijada y nodo en línea, y si no, muestra «no disponible» con el motivo.
- Peticiones firmadas con secretos en `CC-ENV-1` para el dueño, encabezados `X-CC-*`, HTTPS con huella fijada cuando ambos nodos lo ofrecen.
- Manejo de `200`, `202` (consulta de `jobId`) y `problem+json`; los paquetes recibidos se validan con §13.1 y los `result` se abren con la llave propia.
- Reenvío a bandejas ajenas con re-firma, conservando `producerNode` y `keyRef`.
- `tools/CentroCiber.MockNode`: nodo simulado EQ01 con `AESGCM`, usable en pruebas y desde la línea de comandos.
- Prueba de punta a punta entre dos nodos (EQ08 ↔ EQ09) para `HASHSHA` y `HMACSHA256`: forward → bandeja → aceptar → inverse delegado.

### Fase 6 — Descubrimiento y directorio

#### Agregado

- Anuncio `CC-BEACON` por UDP 5099 al iniciar, cada 30 s y `offline` al apagar, a `255.255.255.255` y al broadcast de cada interfaz; oyente con `ReuseAddress` que ignora anuncios propios y de otras versiones.
- Escaneo HTTP de respaldo de la /24 en los puertos 5001–5020 (500 ms, 64 en paralelo, ciclo automático limitado a 5 min).
- Directorio con alta manual, verificación de `status`/`certificate` (CN y huella), confianza en el primer uso, alerta de cambio de huella y paso a `offline` a los 90 s.
- Scripts `scripts/run-two-nodes.sh` y `.ps1` para levantar EQ08 y EQ09 en una sola máquina.
- Los clientes HTTP hacia otros nodos no usan el proxy del sistema.

### Fase 5 — API de proveedor

#### Agregado

- Endpoints `GET /api/status`, `/api/certificate`, `/api/algorithms`, `/api/keys/{keyId}` (siempre `E-KEY-NOT-FOUND`), `POST /api/requests/receive`, `/api/crypto/forward`, `/api/crypto/inverse`, `GET /api/jobs/{jobId}` y `/result`.
- Validación de peticiones `/api/crypto/*` con los 8 pasos de §13.2; resultados de `inverse` cifrados con `CC-ENV-1` para el solicitante.
- Errores `application/problem+json` con los 29 códigos del Anexo B; encabezados `X-CC-Node` y `X-CC-Protocol` en las respuestas.
- Cola de trabajos (tope síncrono de 30 s configurable, `202` con `jobId`, retención de 1 h, descarga solo para el solicitante).
- HTTPS en `5100 + teamNumber` con el certificado de identidad.
- Límite de 10 peticiones `/api/crypto/*` simultáneas (`E-BUSY`) y `acceptingPackages` desde Ajustes.
- Documento OpenAPI en `docs/api/openapi.json`, con una prueba que avisa si queda desactualizado.
- ADR 0001–0013 con las decisiones e interpretaciones del estándar.

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
