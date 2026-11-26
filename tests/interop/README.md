# Pruebas de interoperabilidad (Python + `cryptography`)

Este directorio contiene una implementación **independiente** de las primitivas del estándar v2.0, escrita en Python con la librería [`cryptography`](https://cryptography.io/). No comparte código con la implementación .NET. Sirve para demostrar que lo que produce EQ08 lo puede leer otro lenguaje, y al revés (§16.2 «Sobre `CC-ENV-1` interoperable en ambos sentidos»).

| Archivo | Para qué |
| --- | --- |
| `cc_interop.py` | Primitivas en Python: hash canónico (§8.5), cadena de firma (§8.4), RSA-PSS (§8.2), sobre `CC-ENV-1` (§8.3), validación de paquetes (§13.1 #1–#13) |
| `verify_package.py` | Herramienta de línea de comandos que verifica un `.zip` v2.0 (de EQ08 o de cualquier equipo) |
| `make_envelope.py` | Crea un sobre `CC-ENV-1` en Python para que .NET lo abra |
| `test_primitives.py` | Verifica certificado, firma, hash canónico y sobre generados por .NET |
| `test_packages.py` | Verifica los paquetes `package`/`result` generados por .NET |
| `test_vectors.py` | Verifica los vectores públicos `vectores/EQ08/` |

## Requisitos

```bash
python3 -m pip install -r tests/interop/requirements.txt
```

## Cómo se ejecutan

1. **Dentro de `dotnet test`** (lo normal): la prueba `InteropBridgeTests` de `tests/CentroCiber.Packaging.Tests` genera los artefactos en `artifacts/interop/` y luego ejecuta `python -m pytest tests/interop`. Si Python o `cryptography` no están instalados, la prueba **falla** con un mensaje que lo indica; no se omite. La misma clase crea un sobre en Python y comprueba que .NET lo abre.
2. **Por separado** (por ejemplo, en la CI después de `dotnet test`):

   ```bash
   dotnet test CentroCiber.slnx
   python3 -m pytest tests/interop -q
   ```

   Si quieres usar otra carpeta de artefactos, define `CC_INTEROP_DIR`.

3. **Verificar un paquete suelto**, propio o de otro equipo:

   ```bash
   python3 tests/interop/verify_package.py vectores/EQ08/HASHSHA_ejemplo.zip
   python3 tests/interop/verify_package.py paquete.zip --check-time
   python3 tests/interop/verify_package.py RES_EQ08_....zip --private-key vectores/EQ08/privada-PRUEBA.pem
   ```

   Si el paquete es válido, sale con código 0 e imprime `VÁLIDO ...`. Si no, imprime `INVÁLIDO E-...` y sale con código 1.
