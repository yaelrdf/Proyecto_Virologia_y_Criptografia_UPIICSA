# Interoperabilidad

Cómo comprobar que EQ08 se entiende con los nodos de los demás equipos, siguiendo §16 del estándar v2.0.

- [Matriz de interoperabilidad](Matriz.md): qué combinaciones se probaron, cuándo y con qué resultado (§16.3).
- [Lista de conformidad §16.2](Conformidad.md), con evidencia.
- [Vectores públicos de EQ08](../../vectores/EQ08/README.md) (§16.1).
- [Compatibilidad con RelayCryptoNode (EQ06)](RelayCryptoNode.md).

## 1. Antes de la prueba integrada

1. **Intercambiar huellas** por un canal confiable (en persona o en el chat del grupo). La de EQ08 aparece en la barra de estado y en *Ajustes*.
2. **Validar los vectores del otro equipo** (sección 3) antes de conectarse: así se separan los errores de formato de los de red.
3. **Red**: mismo router o hotspot, firewall abierto (`scripts/firewall-*.{sh,ps1}`) y relojes con NTP.

## 2. Probar contra otro equipo

1. Arranca EQ08 y entra a **Nodos**. El otro nodo debe aparecer por anuncio UDP; si no, usa **Buscar nodos** o **Alta manual** (`IP` y `5000 + n`).
2. Compara su huella observada con la que te dieron y pulsa **Confirmar huella**.
3. **EQ08 como solicitante**: en **Operar (ida)** elige un algoritmo del otro equipo. El formulario se genera con su perfil `/api/algorithms`. Ejecuta `forward`. El paquete aparece en Consultas (`Generado`, productor = el otro equipo). Después, en **Operar (vuelta)**, ejecuta `inverse` con la misma clave.
4. **EQ08 como proveedor**: el otro equipo pide `HASHSHA` o `HMACSHA256` a EQ08. Revisa *Ajustes → Bitácora* (`crypto.forward`, `crypto.inverse`).
5. **Bandejas**: envía un paquete desde Consultas con **Reenviar a…**. El otro equipo debe verlo en su bandeja con «Firma OK» y poder aceptarlo. Haz lo mismo en sentido contrario y acepta en **Solicitudes**.
6. **Rechazos** (§16.2): el otro equipo envía un zip con 4 archivos, uno con el hash alterado, uno con la firma alterada, uno con un timestamp viejo y otro repetido. EQ08 debe responder `E-ZIP-STRUCTURE`, `E-HASH`, `E-SIGNATURE`, `E-TIMESTAMP` y `E-DUPLICATE`.
7. Para pruebas rápidas usa **Enviar** (mandar un paquete a su bandeja) y **Bandeja** (ver y descifrar lo que te mandan). Si algo se rechaza, **Bandeja → Rechazos recientes** muestra el código y el detalle exactos.
8. Anota cada combinación en la [matriz](Matriz.md), con fecha, resultado y código de error si lo hubo.

Herramientas útiles:

```bash
curl -s http://<ip>:<puerto>/api/status          # ¿responde?, ¿hora del servidor?
```

```bash
curl -s http://<ip>:<puerto>/api/algorithms      # nombres de parámetros del dueño
```

```bash
python3 tests/interop/verify_package.py paquete_recibido.zip --check-time
```

Sin otros equipos, la delegación se puede ensayar contra el nodo simulado EQ01 (AESGCM):

```bash
dotnet run --project tools/CentroCiber.MockNode -- --port 5001 --bind 0.0.0.0
```

## 3. Validar los vectores de otro equipo

1. Copia su carpeta a `vectores/EQNN/`.
2. Verifica cada paquete con la implementación independiente en Python:

   ```bash
   for z in vectores/EQNN/*_ejemplo.zip; do python3 tests/interop/verify_package.py "$z"; done
   ```

   Si hay un `result` y publicaron la llave de PRUEBA:

   ```bash
   python3 tests/interop/verify_package.py vectores/EQNN/X_resultado.zip --private-key vectores/EQNN/privada-PRUEBA.pem
   ```

3. Compara su `cadena-firma.txt` y su `params-canonicos.txt` con lo que calcula `cc_interop.signature_chain` y `cc_interop.canonical_text`.
4. Agrega una prueba .NET en `tests/CentroCiber.Packaging.Tests/VectorsTests.cs` (patrón: validar con el reloj fijado en su `timestampUtc`).
5. Errores frecuentes y su causa probable:

   | Código | Causa típica |
   | --- | --- |
   | `E-PARAMS-HASH` | Ordenaron las llaves por UTF-16 o con mayúsculas ignoradas, agregaron un `\n` final o usaron valores que no son cadena |
   | `E-SIGNATURE` | Firmaron el JSON en lugar de la cadena §8.4, usaron PKCS#1 v1.5, o una sal PSS distinta de 32 |
   | `E-CERT-THUMBPRINT` | Huella en minúsculas o con `:` |
   | `E-ZIP-STRUCTURE` | Carpetas dentro del zip o archivos ocultos (`__MACOSX/`, `.DS_Store`) |
   | `E-ENV-DECRYPT` | AAD distinto de `requestId`/`packetId` o tag concatenado de otra forma |
