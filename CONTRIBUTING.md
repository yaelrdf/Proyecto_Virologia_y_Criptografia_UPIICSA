# Cómo contribuir al nodo EQ08

Gracias por ayudar. Este documento explica cómo trabajamos en el Equipo 8.

## Flujo de trabajo

1. **Una sola rama de trabajo** para el desarrollo de una entrega. No se abren PR intermedios; al final se integra a `main` con un solo PR revisado por el equipo.
2. **Un commit por historia** del [backlog](docs/backlog/Backlog.md). Cada historia tiene un ID (`H5.4`) y una prueba de aceptación.
3. Al cerrar una fase (épica): `dotnet build -warnaserror`, `dotnet test` y `pytest tests/interop`. Después, un commit `chore(phase-N): close phase N` que actualice el backlog y el `CHANGELOG.md`, y `git push`.
4. No se declara terminada una historia si sus pruebas no corren. Lo que no se pueda verificar (Windows real, LAN real, otros equipos) se marca 🖐 en el backlog, con el motivo.

## Mensajes de commit

Usamos [Conventional Commits](https://www.conventionalcommits.org/es/v1.0.0/) **en inglés**:

```text
feat(crypto): add CC-ENV-1 envelope
fix(web): serve static web assets outside Development
test(api): cover E-DUPLICATE for repeated requestId
docs(manual): describe firewall setup on Windows
chore(phase-5): close phase 5
```

Tipos: `feat`, `fix`, `test`, `docs`, `refactor`, `build`, `ci`, `chore`. Ámbitos usuales: `crypto`, `packaging`, `api`, `discovery`, `delegation`, `ui`, `infrastructure`, `scripts`, `adr`.

## Estilo de código

- El código, los identificadores, los comentarios técnicos y los commits van en **inglés**. La interfaz, los mensajes al usuario, el `detail` de los errores y la documentación van en **español**.
- Se sigue el `.editorconfig` del repositorio: `namespace` de archivo, `async` de punta a punta con `CancellationToken`, y rutas siempre con `Path.Combine`.
- Los literales del protocolo (puertos, códigos `E-...`, nombres de archivo del zip, códigos de algoritmo) salen de `ProtocolConstants`, `ErrorCodes` y `AlgorithmCatalog`. Nunca van sueltos en el código.
- Las advertencias son errores (`TreatWarningsAsErrors`). Antes del commit: `dotnet format CentroCiber.slnx`.
- Toda regla «DEBE» del estándar que se implemente lleva una prueba que la cite (`// Estándar §13.1 #8`).

## Compilar y probar

```bash
dotnet tool restore
dotnet build CentroCiber.slnx -warnaserror
dotnet test CentroCiber.slnx
python3 -m pip install -r tests/interop/requirements.txt
python3 -m pytest tests/interop -q
```

- Pruebas de interoperabilidad: ver [`tests/interop/README.md`](tests/interop/README.md).
- El documento OpenAPI se regenera con `scripts/export-openapi.sh`. La prueba `Openapi_document_is_up_to_date` falla si queda desactualizado.
- Migraciones de BD: `dotnet tool run dotnet-ef migrations add <Nombre> -p src/CentroCiber.Infrastructure -s src/CentroCiber.Infrastructure -o Data/Migrations`.

## Documentación

Si cambia el comportamiento, la documentación se actualiza **en el mismo commit**: README, manuales, `docs/api/`, `docs/base-de-datos/` y, si hay una decisión nueva o una interpretación del estándar, un ADR en `docs/arquitectura/decisiones/`. El `CHANGELOG.md` sigue *Keep a Changelog*, con una entrada por fase.

## Agregar vectores de otros equipos

1. Copia su carpeta `vectores/EQNN/` (del repositorio compartido, §17) a `vectores/EQNN/` en este repositorio.
2. Verifica cada paquete con la herramienta independiente:

   ```bash
   python3 tests/interop/verify_package.py vectores/EQNN/AESGCM_ejemplo.zip
   ```

3. Si es válido, agrega un caso a `tests/CentroCiber.Packaging.Tests/VectorsTests.cs`, validando con el reloj fijado en el `timestampUtc` del vector.
4. Registra el resultado, con fecha, en [`docs/interoperabilidad/Matriz.md`](docs/interoperabilidad/Matriz.md). Si falla, anota el código `E-...` y avísale al equipo dueño.

Más detalle en [`docs/interoperabilidad/README.md`](docs/interoperabilidad/README.md).
