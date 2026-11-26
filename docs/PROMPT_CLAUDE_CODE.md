# Prompt para la sesión de Claude Code (desarrollo completo del nodo EQ08)

Copia todo lo que está entre las líneas `=====` y pégalo como primer mensaje de una sesión de Claude Code en la nube sobre este repositorio. El entorno debe tener acceso de red **Trusted** y el setup script `scripts/cloud-setup.sh`.

=====

Eres el desarrollador principal del **nodo EQ08** del Centro de Ciberseguridad Comunitario. Tu tarea es construir el proyecto **completo**: código, pruebas, scripts y toda la documentación, listo para entregarse y para hacer la demo en Windows y Linux.

## 0. Antes de escribir código

1. Lee completos, en este orden: `CLAUDE.md`, `docs/estandar/Estandar_Comunicacion_v2.0.md`, `docs/plan/Plan_Implementacion_EQ08.md`, `docs/referencia/Requerimientos_proyecto.md`, `docs/referencia/Equipos_algoritmos.md`. El estándar v2.0 es normativo; el plan define fases y criterios de aceptación.
2. Verifica el entorno: `dotnet --list-sdks` debe mostrar 10.x. Si no, ejecuta `sudo bash scripts/cloud-setup.sh`.
3. Crea `docs/backlog/Backlog.md` a partir de las 9 fases del plan: una épica por fase, una historia por criterio o entregable, cada historia con su prueba de aceptación y la sección del estándar que cubre. Marca las historias conforme las cierres. Este backlog es un entregable del curso.
4. Crea la rama de trabajo (si la sesión no creó una) y trabaja en ella hasta el final. Un commit por historia (Conventional Commits en inglés) y un commit de cierre por fase. Haz `push` al final de cada fase.

## 1. Fases a implementar (en orden; no saltes criterios)

Sigue las 9 fases de `docs/plan/Plan_Implementacion_EQ08.md` §6. Puntos que DEBES cubrir además de lo que dice el plan:

**Fase 1 — Base multiplataforma**
- Solución `CentroCiber.slnx` con la estructura de `CLAUDE.md`, `Directory.Build.props`, `Directory.Packages.props`, `.editorconfig`, `.config/dotnet-tools.json` (con `dotnet-ef`).
- Amplía `.gitignore` (sin borrar lo existente): `*.pfx`, `*.p12`, `*.db`, `*.db-*`, `data/`, `storage/`, `secrets*.json`, `.env`, excepto `vectores/**`.
- EF Core + SQLite, migración inicial, semilla de 38 registros (21 algoritmos del diccionario 4.1, 8 equipos, 1 nodo propio, 4 paquetes, 3 solicitudes, 1 settings).
- Configuración por `appsettings.json` + variables de entorno con prefijo `CC_` (puertos, rutas de datos, límites).
- `.github/workflows/ci.yml`: build + test en `ubuntu-latest` y `windows-latest` con .NET 10, y publicación de artefactos `win-x64` y `linux-x64` autocontenidos.

**Fase 2 — Identidad y primitivas**: PFX (genera si no existe, carga con `CC_PFX_PASSWORD`), certificado según §7, RSA-PSS, sobre `CC-ENV-1`, hash canónico §8.5, cadena de firma §8.4. Incluye `tests/interop/` en Python (`cryptography`) que verifica firma, hash canónico y sobre generados por .NET, y que crea un sobre que .NET abre. Integra esas pruebas en `dotnet test` (o en un paso de CI) y documenta cómo correrlas.

**Fase 3 — Algoritmos propios**: `HASHSHA` (SHA-256/512) y `HMACSHA256` como `IAlgorithmProvider` local. Vectores NIST y RFC 4231 en pruebas.

**Fase 4 — Paquetes v2.0**: constructor/validador `package` y `result`, nomenclatura, `multipart`, reenvío con re-firma, las 14 validaciones de §13.1 en orden, con una prueba por cada código de error (incluye zip-slip, zip-bomb, 4 archivos, timestamp viejo, `packetId` repetido).

**Fase 5 — API de proveedor**: los endpoints de §10 (`status`, `certificate`, `algorithms`, `requests/receive`, `crypto/forward`, `crypto/inverse`, `jobs/{id}`, `jobs/{id}/result`), encabezados `X-CC-*`, `problem+json` con el catálogo del Anexo B, cola de trabajos (tope 30 s, retención 1 h), HTTP 5008 + HTTPS 5108. Genera el documento OpenAPI (paquete `Microsoft.AspNetCore.OpenApi`) y guárdalo en `docs/api/openapi.json`.

**Fase 6 — Descubrimiento**: anuncio y oyente UDP 5099 (§6.1), escaneo /24 en 5001–5020 (§6.2), alta manual, TOFU y alerta de cambio de huella (§6.3). Prueba con dos instancias en loopback en puertos distintos. Script `scripts/run-two-nodes.sh` (y `.ps1`) que levanta dos nodos locales para demo.

**Fase 7 — Cliente de delegación**: proveedor remoto para los 19 algoritmos ajenos: petición firmada, sobre para el dueño, `200`/`202`/errores, consulta de `jobId`, `keyRef`, reenvío a bandeja ajena. Implementa `MockNode` (en el proyecto de pruebas y como herramienta ejecutable opcional `tools/CentroCiber.MockNode`) que simula a `EQ01` con `AESGCM` según el estándar, para probar sin otros equipos.

**Fase 8 — Interfaz web**: las 6 pantallas del plan §5 en español, formularios generados desde los perfiles `GET /api/algorithms`, filtro solo-LAN, barra de estado, notificaciones en tiempo real. Aplica la identidad visual definida en el manual de identidad (ver §2). Pruebas bUnit de los componentes clave.

**Fase 9 — Conformidad, vectores y documentación**: `vectores/EQ08/` completo según §16.1 (con llave marcada PRUEBA), lista de conformidad §16.2 marcada con evidencia, matriz de interoperabilidad inicial en `docs/interoperabilidad/Matriz.md`, scripts de firewall (`scripts/firewall-windows.ps1` con `netsh`/`New-NetFirewallRule`, `scripts/firewall-linux.sh` con `ufw`), scripts de publicación, y toda la documentación de §2.

## 2. Documentación que DEBE quedar en el repositorio (en español)

| Archivo | Contenido mínimo |
| --- | --- |
| `README.md` | Qué es el nodo EQ08 y el Centro; algoritmos propios y delegados; captura o diagrama; requisitos; inicio rápido (Linux y Windows); puertos; variables de entorno; estructura del repo; enlaces a toda la documentación; equipo (dejar marcadores `<!-- TODO: integrantes -->`); licencia GPL-3.0 |
| `CONTRIBUTING.md` | Flujo de trabajo (una rama, commits por historia), Conventional Commits, estilo de código, cómo correr build/test/interop, cómo actualizar backlog/CHANGELOG/documentación, cómo agregar vectores de otros equipos |
| `CODE_OF_CONDUCT.md` | Código de conducta breve y propio del equipo; puede enlazar a Contributor Covenant 2.1 sin copiarlo |
| `SECURITY.md` | Cómo reportar vulnerabilidades, manejo del PFX y contraseñas, qué nunca debe subirse, alcance académico |
| `CHANGELOG.md` | Formato *Keep a Changelog*; una entrada por fase |
| `docs/manuales/Manual_Tecnico.md` | Arquitectura (con diagramas Mermaid), proyectos y dependencias, flujo de cada endpoint, modelo de datos, criptografía usada y por qué, decisiones (enlace a ADRs), cómo extender con un nuevo algoritmo local |
| `docs/manuales/Manual_Instalacion_Configuracion.md` | Paso a paso en Windows y Linux: requisitos, publicación o binario, `CC_PFX_PASSWORD`, firewall, primer arranque, confirmar nodos (TOFU), HTTPS, solución de problemas (broadcast bloqueado, reloj, puertos ocupados) |
| `docs/manuales/Manual_Identidad.md` | Propón tú: nombre del producto para el nodo, logotipo **original** en SVG (`docs/assets/logo.svg`, sin marcas de terceros), paleta con códigos hex y contraste AA verificado, tipografías libres, iconografía, tono de voz, uso correcto/incorrecto. Márcalo como “propuesta para aprobación del equipo” |
| `docs/manuales/Reporte_General.md` | Plantilla del reporte con lo realizado: objetivos, arquitectura, resultados de pruebas reales (copiados de la ejecución), conformidad, matriz de interoperabilidad, problemas y lecciones, trabajo futuro; marcadores para lo que el equipo debe completar |
| `docs/backlog/Backlog.md` | Épicas, historias, criterios, estado |
| `docs/api/` | `openapi.json` generado + `README.md` con ejemplos `curl` de cada endpoint |
| `docs/base-de-datos/` | Diagrama ER en Mermaid, diccionario de datos por tabla, descripción de la semilla (≥ 30 registros) |
| `docs/arquitectura/decisiones/` | ADRs (`0001-dotnet-10.md`, `0002-blazor-server.md`, `0003-sqlite.md`, `0004-pfx-password-env.md`, más las interpretaciones del estándar que hayas tenido que tomar) |
| `docs/interoperabilidad/` | `Matriz.md`, cómo probar contra otro equipo, cómo validar sus vectores |

La licencia ya existe (`LICENSE`, GPL-3.0): no la modifiques; agrega el aviso de licencia en el README.

## 3. Reglas de trabajo

- El estándar v2.0 manda. Si algo es ambiguo, decide lo más conservador, escríbelo en un ADR y en “Pendientes” del backlog; no detengas el trabajo por eso.
- No preguntes salvo que estés bloqueado de verdad (por ejemplo, falta de red para NuGet). En ese caso, explica el bloqueo y continúa con lo que no dependa de él.
- Después de cada fase: `dotnet build -warnaserror`, `dotnet test`, pruebas de interoperabilidad; actualiza backlog y CHANGELOG; commit de cierre; push.
- Nunca subas secretos reales. Nunca inventes resultados de pruebas ni marques como hecho algo que no se ejecutó.
- Lo que no se puede verificar en la nube (Windows real, LAN real, otros equipos) déjalo documentado como verificación manual pendiente en el backlog y en el manual de instalación.

## 4. Definición de terminado (todo el proyecto)

- [ ] Las 9 fases cerradas con sus criterios verificados (o marcados como verificación manual pendiente con motivo).
- [ ] `dotnet build -warnaserror` y `dotnet test` en verde en Linux; CI en verde en Ubuntu y Windows.
- [ ] Publicación autocontenida `win-x64` y `linux-x64` generada por la CI.
- [ ] Dos nodos locales se descubren, se confían (TOFU) e intercambian un paquete HASHSHA y uno HMACSHA256 de punta a punta (`forward` → bandeja → aceptar → `inverse`).
- [ ] Delegación de AESGCM contra `MockNode` de punta a punta.
- [ ] Todos los documentos de §2 existen, están en español y enlazados desde el README.
- [ ] `vectores/EQ08/` completo y verificado por el script Python.
- [ ] BD con ≥ 30 registros de semilla.

Al terminar, entrega un resumen corto: qué quedó listo, resultados de pruebas, qué requiere verificación manual del equipo (Windows, LAN, otros equipos) y cualquier ADR que el equipo deba aprobar.

=====
