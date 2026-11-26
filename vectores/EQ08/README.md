# Vectores de prueba de EQ08 (§16.1)

Vectores públicos del nodo **EQ08** (Equipo 8) para que los demás equipos validen su implementación del Estándar de Comunicación v2.0.

> ⚠️ **`privada-PRUEBA.pem` es una llave SOLO DE PRUEBA**, generada para estos vectores con `tools/CentroCiber.VectorGen`. **No** es la llave de identidad real del nodo EQ08 y nunca debe usarse fuera de pruebas.

| Archivo | Contenido |
| --- | --- |
| `certificado.pem` | Certificado de PRUEBA del nodo (`CN=EQ08, OU=Equipo 08, O=Centro de Ciberseguridad, C=MX`, RSA-2048, 365 días) |
| `privada-PRUEBA.pem` | Llave privada PKCS#8 de PRUEBA del certificado anterior |
| `cadena-firma.txt` | Cadena de firma §8.4 de `HASHSHA_ejemplo.zip` (sin salto de línea final) |
| `params-canonicos.txt` | Texto canónico §8.5 de los `publicParameters` de `HASHSHA_ejemplo.zip`, una línea `---` y su SHA-256 |
| `HASHSHA_ejemplo.zip` | Paquete `package` de `HASHSHA` (SHA-256) |
| `HASHSHA_secretos.json` | `{}` (HASHSHA no usa secretos) |
| `HASHSHA_original.txt` | Archivo original (es igual a `datos.enc`) |
| `HASHSHA_resultado.zip` | Paquete `result` de `inverse` con el original cifrado (`CC-ENV-1`) para el certificado de PRUEBA |
| `HMACSHA256_ejemplo.zip` | Paquete `package` de `HMACSHA256` |
| `HMACSHA256_secretos.json` | Clave HMAC de PRUEBA en Base64 (32 bytes `00 01 … 1F`) |
| `HMACSHA256_original.txt` | Archivo original |
| `nombres.json` | Nombre oficial (§9.2) de cada zip; aquí se guardan con nombres fijos para facilitar las pruebas |

## Datos del certificado de PRUEBA

- Huella SHA-256: `CD2F4ACE8FAE143730B5C67460AEE243BC396285645B0F512637A3E58E42184D`
- Vigencia: 2026-11-26 18:25 UTC → 2027-11-26 18:35 UTC (`NotBefore` adelantado 10 min, ADR 0012).
- Los paquetes tienen `timestampUtc` del 2026-11-26: valídalos con la ventana de ±10 min desactivada o con el reloj fijado en esa fecha.

## Cómo validarlos

```bash
python3 tests/interop/verify_package.py vectores/EQ08/HASHSHA_ejemplo.zip
python3 tests/interop/verify_package.py vectores/EQ08/HASHSHA_resultado.zip --private-key vectores/EQ08/privada-PRUEBA.pem
python3 -m pytest tests/interop/test_vectors.py -q
```

En .NET: `dotnet test --filter VectorsTests`.

## Regenerarlos

```bash
dotnet run --project tools/CentroCiber.VectorGen -- vectores/EQ08
```

Al regenerarlos cambian la huella, los `packetId` y las fechas: actualiza este README y avisa a los demás equipos.
