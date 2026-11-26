# Backlog — Nodo EQ08

Backlog del producto derivado de las 9 fases de [`docs/plan/Plan_Implementacion_EQ08.md`](../plan/Plan_Implementacion_EQ08.md) §6. Cada fase es una **épica** y cada criterio o entregable es una **historia** con su prueba de aceptación y la sección del [estándar v2.0](../estandar/Estandar_Comunicacion_v2.0.md) que cubre.

Estados: ⬜ Pendiente · 🟨 En curso · ✅ Hecha (verificada en Linux) · 🖐 Verificación manual pendiente (requiere Windows real, LAN real u otros equipos).

## E1 — Base multiplataforma

| ID | Historia | Prueba de aceptación | Estándar | Estado |
| --- | --- | --- | --- | --- |
| H1.1 | Solución `CentroCiber.slnx` con 6 proyectos `src/`, pruebas y herramientas; `Directory.Build.props`, CPM, `.editorconfig`, `dotnet-ef` local | `dotnet build -warnaserror` sin advertencias | — | ✅ |
| H1.2 | `.gitignore` ampliado (PFX, BD, datos, secretos) | `git check-ignore` sobre `x.pfx`, `a.db`, `data/` | §7, §13.3 | ✅ |
| H1.3 | Constantes del protocolo y diccionario 4.1 centralizados | Prueba de catálogo: 21 algoritmos, códigos y equipos | §3, §4.1, Anexo C | ✅ |
| H1.4 | EF Core + SQLite con migración inicial y semilla de 38 registros | Prueba que cuenta ≥ 30 registros tras migrar | — | ✅ |
| H1.5 | Configuración `appsettings.json` + variables `CC_` | Prueba de enlace de opciones con variable de entorno | §5.1 | ✅ |
| H1.6 | Host responde `GET /api/status` en 5008 | Prueba `WebApplicationFactory` | §10.3 | ✅ |
| H1.7 | CI Ubuntu/Windows y publicación autocontenida `win-x64`/`linux-x64` | Workflow `ci.yml`; `dotnet publish` local para ambos RID | — | ✅ |

## E2 — Identidad y primitivas

| ID | Historia | Prueba de aceptación | Estándar | Estado |
| --- | --- | --- | --- | --- |
| H2.1 | Generar/cargar PFX con `CC_PFX_PASSWORD`; certificado RSA-2048 según §7 | Pruebas de sujeto, vigencia, serie, usos y huella | §7 | ✅ |
| H2.2 | Firma RSA-PSS-SHA256 (sal 32) | Firma/verificación y rechazo de alteración | §8.2 | ✅ |
| H2.3 | Sobre híbrido `CC-ENV-1` | Ida y vuelta, destinatario incorrecto, AAD alterado | §8.3 | ✅ |
| H2.4 | Hash canónico de `publicParameters` y cadena de firma | Ejemplo del §8.5 y del §8.4 | §8.4, §8.5 | ✅ |
| H2.5 | Interoperabilidad con Python `cryptography` en ambos sentidos | `pytest tests/interop` invocado desde `dotnet test` | §8, §16.2 | ✅ |

## E3 — Algoritmos propios

| ID | Historia | Prueba de aceptación | Estándar | Estado |
| --- | --- | --- | --- | --- |
| H3.1 | `IAlgorithmProvider` + `HASHSHA` (SHA-256/512) local | Vectores NIST FIPS 180-4 | §4.2, §4.3 | ✅ |
| H3.2 | `HMACSHA256` local con comparación en tiempo constante | Vectores RFC 4231 casos 1–7 | §4.2, §13.3 | ✅ |

## E4 — Paquetes v2.0

| ID | Historia | Prueba de aceptación | Estándar | Estado |
| --- | --- | --- | --- | --- |
| H4.1 | Manifiesto y constructor `package`/`result` con nomenclatura | Nombre `EQ08_HASHSHA_..._XXXXXXXX.zip` y `RES_...` | §9.1, §9.2, §9.5 | ✅ |
| H4.2 | Contenido `multipart` (zip interno, `parts`) | Ida y vuelta + parte alterada → `E-HASH` | §9.4 | ✅ |
| H4.3 | Reenvío con re-firma | Conserva `datos.enc`, `producerNode`; nuevo `packetId` | §9.6 | ✅ |
| H4.4 | Las 14 validaciones de recepción en orden | Una prueba por código (incl. zip-slip, zip-bomb, 4 archivos, timestamp viejo, `packetId` repetido) | §13.1 | ✅ |

## E5 — API de proveedor

| ID | Historia | Prueba de aceptación | Estándar | Estado |
| --- | --- | --- | --- | --- |
| H5.1 | `GET /api/status`, `/api/certificate`, `/api/algorithms` | Pruebas de API | §10.3, §10.4 | ⬜ |
| H5.2 | Errores `problem+json` con el catálogo del Anexo B y encabezados `X-CC-*` | Prueba del catálogo de 29 códigos | §10.1, §14, Anexo B | ⬜ |
| H5.3 | `POST /api/requests/receive` (bandeja) | `202` + `Pendiente`; errores de §13.1 por API | §10.5, §15 | ⬜ |
| H5.4 | `POST /api/crypto/forward` e `inverse` con las 8 validaciones de §13.2 | `forward`/`inverse` de ambos algoritmos; cada código de §13.2 | §10.6, §13.2 | ⬜ |
| H5.5 | Cola de trabajos (`202`, `jobs/{id}`, `/result`, retención 1 h) | Prueba con tope síncrono 0 s | §10.6, §10.7 | ⬜ |
| H5.6 | HTTPS en 5108 con el certificado de identidad | Cliente con huella fijada | §5.2 | ⬜ |
| H5.7 | Documento OpenAPI en `docs/api/openapi.json` | Prueba de que el archivo está al día | §10 | ⬜ |
| H5.8 | Límite de 10 peticiones `/api/crypto/*` simultáneas → `E-BUSY` | Prueba del limitador | §13.3 | ⬜ |

## E6 — Descubrimiento y directorio

| ID | Historia | Prueba de aceptación | Estándar | Estado |
| --- | --- | --- | --- | --- |
| H6.1 | Anuncio UDP cada 30 s y oyente (ignora propios y ajenos de versión) | Prueba de serialización ≤ 1024 B y de filtro | §6.1 | ⬜ |
| H6.2 | Escaneo /24 en 5001–5020 (500 ms, 64 en paralelo, ≥ 5 min automático) | Prueba con nodo en loopback | §6.2 | ⬜ |
| H6.3 | Alta manual, TOFU y alerta de cambio de huella | Pruebas del directorio | §6.3, §6.4 | ⬜ |
| H6.4 | Estado `offline` a los 90 s | Prueba con reloj simulado | §6.1 | ⬜ |
| H6.5 | Dos instancias se descubren en loopback; scripts `run-two-nodes` | Prueba de integración con dos hosts | §6 | ⬜ |

## E7 — Cliente de delegación

| ID | Historia | Prueba de aceptación | Estándar | Estado |
| --- | --- | --- | --- | --- |
| H7.1 | Selección del dueño y «no disponible» | Pruebas de selección (tabla 4.1, reservados) | §4.4, §11.6 | ⬜ |
| H7.2 | `forward` delegado: petición firmada, sobre para el dueño | AESGCM contra `MockNode` | §10.6, §11.2 | ⬜ |
| H7.3 | `inverse` delegado y apertura del `resultEnvelope` | AESGCM contra `MockNode` | §11.4 | ⬜ |
| H7.4 | Manejo de `202` y consulta de `jobId`; errores `problem+json` | `MockNode` en modo asíncrono | §10.7 | ⬜ |
| H7.5 | `keyRef` y reenvío a bandeja ajena | Reenvío a un segundo nodo | §9.6, §11.3, §12 | ⬜ |
| H7.6 | `MockNode` (EQ01/AESGCM) en pruebas y como herramienta | `dotnet run --project tools/CentroCiber.MockNode` | §16 | ⬜ |

## E8 — Interfaz web

| ID | Historia | Prueba de aceptación | Estándar | Estado |
| --- | --- | --- | --- | --- |
| H8.1 | Diseño base, identidad visual y barra de estado | Prueba bUnit de la barra | §2 | ⬜ |
| H8.2 | Operar (ida) con formulario desde el perfil | Prueba bUnit del formulario dinámico | §10.4 | ⬜ |
| H8.3 | Operar (vuelta) con validación paso a paso y veredicto | Recorrido manual | §13.1, §11.4 | ⬜ |
| H8.4 | Solicitudes (Aceptar/Rechazar, «Remitente no confirmado») | Prueba bUnit | §15 | ⬜ |
| H8.5 | Consultas (filtro por origen, manifiesto, descarga, inverse, reenvío) | Recorrido manual | §15 | ⬜ |
| H8.6 | Nodos (directorio, buscar, alta manual, TOFU, alerta) | Prueba bUnit de la alerta | §6.3 | ⬜ |
| H8.7 | Ajustes | Recorrido manual | §7 | ⬜ |
| H8.8 | Filtro solo-LAN para la interfaz | Prueba del middleware | Plan §5 | ⬜ |
| H8.9 | Notificaciones en tiempo real | Prueba del concentrador de eventos | Plan §5 | ⬜ |

## E9 — Conformidad, vectores y documentación

| ID | Historia | Prueba de aceptación | Estándar | Estado |
| --- | --- | --- | --- | --- |
| H9.1 | Vectores `vectores/EQ08/` completos | `verify_package.py` sobre cada zip | §16.1 | ⬜ |
| H9.2 | Lista de conformidad §16.2 con evidencia | Documento | §16.2 | ⬜ |
| H9.3 | Matriz de interoperabilidad inicial | `docs/interoperabilidad/Matriz.md` | §16.3 | ⬜ |
| H9.4 | Scripts de firewall y publicación | Revisión de scripts | §5.1 | ⬜ |
| H9.5 | Documentación completa en español | Enlaces desde el README | — | ⬜ |
| H9.6 | Recorrido de punta a punta con dos nodos | Prueba de integración | §11 | ⬜ |

## Pendientes e interpretaciones

Se completa conforme se registran ADRs en [`docs/arquitectura/decisiones/`](../arquitectura/decisiones/).
