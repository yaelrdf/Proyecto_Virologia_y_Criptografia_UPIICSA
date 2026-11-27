# API REST del nodo EQ08

La API implementa la sección 10 del [Estándar v2.0](../estandar/Estandar_Comunicacion_v2.0.md).

- **Documento OpenAPI 3.1**: [`openapi.json`](openapi.json). Se genera de la API real con `scripts/export-openapi.sh`, y una prueba avisa si quedó desactualizado. El nodo también lo sirve en `GET /openapi/v1.json`.
- **Base:** `http://<ip>:5008` o `https://<ip>:5108` (con el mismo certificado de identidad).
- **Encabezados** de las respuestas: `X-CC-Node: EQ08` y `X-CC-Protocol: 2.0`. Las respuestas de `/api/crypto/*` agregan `X-CC-Request-Id`.
- **Errores:** `application/problem+json` con un `code` del Anexo B (ver la tabla al final).
- **Cuerpo máximo:** 50 MB.
- La API responde a cualquier IP de la LAN; la interfaz web, solo a IP privadas o de loopback.

En los ejemplos, `N=http://192.168.1.14:5008`.

## `GET /api/status` (§10.3)

```bash
curl -s $N/api/status
```

```json
{"nodeId":"EQ08","teamNumber":8,"protocolVersion":"2.0","status":"online","acceptingPackages":true,"httpPort":5008,"httpsPort":5108,"algorithms":[{"algorithmId":15,"algorithmCode":"HASHSHA"},{"algorithmId":16,"algorithmCode":"HMACSHA256"}],"certificateThumbprintSha256":"0D54684120B1FB5FC08C606ABB27B0AD7DE000D65C7B19F5EE472148CA423EDF","serverTimeUtc":"2026-11-26T18:31:19Z","supportedProtocolVersions":["2.0"],"nodeVersion":"1.1.0"}
```

`supportedProtocolVersions` y `nodeVersion` son extensiones desde la versión 1.1.0. Los nodos que no las conocen las ignoran (§9.5); RelayCryptoNode (EQ06) publica un campo equivalente.

## `GET /api/certificate`

Devuelve el certificado de identidad en PEM (`application/x-pem-file`).

```bash
curl -s $N/api/certificate -o EQ08.pem && openssl x509 -in EQ08.pem -noout -subject -fingerprint -sha256
```

## `GET /api/algorithms` (§10.4)

Devuelve los perfiles de `HASHSHA` y `HMACSHA256`: variantes, operaciones, secretos, opciones, `publicParameters`, `payloadModes` y `maxPayloadBytes`.

```bash
curl -s $N/api/algorithms | python3 -m json.tool
```

Los perfiles de otros nodos pueden traer campos extra (por ejemplo `notes` en EQ06). EQ08 los lee y muestra `notes` en el formulario.

## `GET /api/keys/{keyId}`

EQ08 no tiene algoritmos con `keyId`, así que siempre responde `404 E-KEY-NOT-FOUND`.

## `POST /api/requests/receive` (§10.5)

Recibe un paquete en la bandeja de Solicitudes, en la parte `package` de un `multipart/form-data`.

```bash
curl -s -F "package=@EQ05_VIGENERE_20261125_162500_60303AE2.zip;type=application/zip" $N/api/requests/receive
```

```json
{"packetId":"550e8400-e29b-41d4-a716-446655440000","status":"Pendiente","receivedAtUtc":"2026-11-25T15:47:03Z"}
```

Antes de aceptarlo se aplican las 14 validaciones de §13.1. Desde la versión 1.1.0, si el remitente omite campos que no están firmados, se completan y se registran ([ADR 0016](../arquitectura/decisiones/0016-informational-fields-defaults.md)). Si el remitente tiene huella fijada y no coincide, responde `403 E-CERT-UNTRUSTED`. Si el nodo no acepta paquetes (Ajustes), responde `503 E-BUSY`.

## `POST /api/crypto/forward` y `/api/crypto/inverse` (§10.6)

Partes del `multipart/form-data`:

| Parte | `forward` | `inverse` | Contenido |
| --- | :---: | :---: | --- |
| `request` | ✔ | ✔ | JSON de la petición (bytes exactos firmados) |
| `requestSignature` | ✔ | ✔ | Base64 de la firma RSA-PSS-SHA256 de `request` |
| `requesterCertificate` | ✔ | ✔ | PEM del solicitante (CN = `requesterNode`) |
| `payload` | ✔ | — | Archivo, texto o imagen |
| `package` | — | ✔ | Paquete `package` que se va a invertir |

Como la firma y el sobre `CC-ENV-1` no se pueden hacer a mano con `curl`, los ejemplos siguientes usan la implementación independiente de `tests/interop` para armar la petición. El script usa la llave de PRUEBA de los vectores como si fuera el solicitante EQ08 y se lo pide al nodo `$N`. Para pedírselo a otro EQ08, cambia `targetNode` y el certificado de destino.

```bash
python3 - <<'PY'
import base64, json, sys, uuid, datetime, urllib.request
sys.path.insert(0, "tests/interop")
import cc_interop
from cryptography import x509
N = "http://127.0.0.1:5008"
target = x509.load_pem_x509_certificate(urllib.request.urlopen(N + "/api/certificate").read())
me_key = cc_interop.load_private_key(open("vectores/EQ08/privada-PRUEBA.pem", "rb").read())
me_cert = open("vectores/EQ08/certificado.pem").read()
rid = str(uuid.uuid4())
secrets, _ = cc_interop.seal_envelope(json.dumps({"key": base64.b64encode(bytes(32)).decode()}).encode(), target, "EQ08", rid)
req = json.dumps({"version": "2.0", "requestId": rid, "requesterNode": "EQ08", "targetNode": "EQ08",
    "timestampUtc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "algorithmCode": "HMACSHA256", "operation": "forward", "payloadMode": "text", "originalFileName": "mensaje.txt",
    "options": {"macAlgorithm": "HMAC-SHA256"}, "keyId": None, "secrets": secrets}).encode()
open("request.json", "wb").write(req)
open("request.sig", "w").write(cc_interop.sign_pss(me_key, req))
open("payload.txt", "w").write("hola EQ08")
PY
```

```bash
curl -s -o paquete.zip -w "%{http_code} %{content_type}\n" \
  -F "request=@request.json;type=application/json" \
  -F "requestSignature=<request.sig" \
  -F "requesterCertificate=@vectores/EQ08/certificado.pem;type=application/x-pem-file" \
  -F "payload=@payload.txt" \
  -H "X-CC-Node: EQ08" -H "X-CC-Protocol: 2.0" \
  $N/api/crypto/forward
```

```bash
python3 tests/interop/verify_package.py paquete.zip
```

Respuestas:

- `200 application/zip`: `package` en `forward`, o `result` en `inverse`. El `result` lleva `resultado.enc` cifrado con `CC-ENV-1` para el certificado del solicitante y `verification: {valid, detail}`.
- `202`: el trabajo superó el tope síncrono (30 s por omisión).

  ```json
  {"jobId":"7c1e...","statusUrl":"/api/jobs/7c1e...","retryAfterSeconds":5}
  ```

- Errores posibles (§13.2, en orden): `E-REQUEST`, `E-SIZE`, los de §13.1 sobre el `package` (en `inverse`), `E-VERSION`, `E-CERT`, `E-CERT-UNTRUSTED`, `E-REQUEST-SIGNATURE`, `E-TIMESTAMP`, `E-DUPLICATE`, `E-ALGORITHM`, `E-ALGORITHM-NOT-PROVIDED`, `E-ENV-RECIPIENT`, `E-ENV-DECRYPT`, `E-PARAMS`, `E-BUSY` y `E-UNSUPPORTED-MEDIA`.

Para `inverse` se envía `package=@paquete.zip;type=application/zip` en lugar de `payload`, con `"operation":"inverse"` en la petición.

## `GET /api/jobs/{jobId}` y `/api/jobs/{jobId}/result` (§10.7)

Consultar el estado del trabajo:

```bash
curl -s $N/api/jobs/7c1e....
```

```json
{"jobId":"7c1e...","state":"done","progressPercent":100,"resultUrl":"/api/jobs/7c1e.../result","error":null}
```

Descargar el resultado (solo para el solicitante original):

```bash
curl -s -H "X-CC-Node: EQ03" -o resultado.zip $N/api/jobs/7c1e.../result
```

Los resultados se conservan al menos 1 h. Si el `jobId` no existe o expiró, o si `X-CC-Node` no es el solicitante, la respuesta es `404 E-JOB-NOT-FOUND`.

## Formato de error (§14)

```json
{"type":"https://centrociber.local/errors/E-HASH","title":"Integridad inválida","status":422,"code":"E-HASH","detail":"El SHA-256 de datos.enc no coincide con encryptedSha256.","nodeId":"EQ08","requestId":null,"timestampUtc":"2026-11-25T15:47:04Z"}
```

| Código | HTTP | ¿Lo devuelve EQ08? |
| --- | :---: | --- |
| `E-SIZE`, `E-ZIP-INVALID`, `E-ZIP-STRUCTURE`, `E-ZIP-BOMB`, `E-MANIFEST`, `E-VERSION`, `E-ALGORITHM`, `E-HASH`, `E-PARAMS-HASH`, `E-CERT`, `E-CERT-THUMBPRINT`, `E-SIGNATURE`, `E-TIMESTAMP`, `E-DUPLICATE`, `E-CERT-UNTRUSTED` | 413/400/422/409/403 | Sí (§13.1) |
| `E-REQUEST`, `E-REQUEST-SIGNATURE`, `E-ENV-RECIPIENT`, `E-ENV-DECRYPT`, `E-ALGORITHM-NOT-PROVIDED`, `E-PARAMS`, `E-UNSUPPORTED-MEDIA` | 400/401/404/415 | Sí (§13.2) |
| `E-JOB-NOT-FOUND`, `E-KEY-NOT-FOUND`, `E-BUSY`, `E-INTERNAL` | 404/503/500 | Sí |
| `E-KEY-FORBIDDEN` | 403 | No (EQ08 no guarda llaves) |
| `E-VERIFY-FAILED` | 422 | No: `valid:false` va en `verification` ([ADR 0008](../arquitectura/decisiones/0008-verify-failed.md)) |
| `E-TIMEOUT` | 504 | No: EQ08 siempre crea un trabajo asíncrono |
