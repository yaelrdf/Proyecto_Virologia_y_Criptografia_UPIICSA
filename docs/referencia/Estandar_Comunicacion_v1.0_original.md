# Propuesta de Estándar de Intercambio `.ZIP` entre Nodos (Protocolo por IP)

**Propósito:** Estandarizar el empaquetado, nomenclatura, protocolo de envío/recepción por dirección IP y reglas de validación criptográfica entre células de trabajo del **Centro de Ciberseguridad**, independientemente del lenguaje o framework que utilice cada equipo (.NET, Java, Node.js, Python, etc.).

---

## 0. Requisito Operativo Obligatorio por Equipo (Modos de Envío y Recepción)

Para garantizar la interoperabilidad bidireccional dentro de la red del **Centro de Ciberseguridad**, **cada equipo / célula de trabajo debe implementar obligatoriamente ambos modos operativos**:

1. **Modo de Envío (Emisor):**
   - Capacidad de cifrar (o procesar) un texto, archivo o imagen, generar el paquete `.zip` con los 3 archivos obligatorios (`datos.enc`, `certificado.pem`, `manifest.json`) siguiendo la nomenclatura oficial y enviarlo mediante HTTP `POST` a la dirección `IP:Puerto` de otro equipo (desde un panel o consulta de registros).
2. **Modo de Recepción (Receptor):**
   - Servidor HTTP activo en red local (LAN) escuchando paquetes `.zip` entrantes en `POST /api/requests/receive`, validando su estructura, `SHA-256` y firma X.509, y presentándolos en una bandeja de **`Solicitudes`** para que el usuario decida **`Aceptar`** (almacenándolo en su base de datos/consultas) o **`Rechazar`**.

---

## 1. Nomenclatura Estándar del Archivo `.ZIP`

Todo paquete enviado entre nodos debe seguir una nomenclatura determinista y legible que evite colisiones y permita identificar el origen sin descomprimirlo:

```text
<NODO_ORIGEN>_<ALGORITMO>_<YYYYMMDD_HHMMSS>_<SHA8>.zip
```

* **`<NODO_ORIGEN>`:** Identificador de la célula emisora en mayúsculas sin espacios (ej. `NODO01`, `CELULA03`).
* **`<ALGORITMO>`:** Código corto oficial en **MAYÚSCULAS** sin guiones ni espacios, tomado exactamente de la tabla `1.1` (ej. `AESGCM`, `RSA`, `CHACHA20`, `LSBSTEGO`).
* **`<YYYYMMDD_HHMMSS>`:** Marca de tiempo UTC del empaquetado.
* **`<SHA8>`:** Primeros 8 caracteres hexadecimales del `SHA-256` del archivo `datos.enc`.

**Ejemplo válido:**
`NODO01_AESGCM_20261116_212000_9F86D081.zip`

### 1.1 Tipos de Cifrado y Códigos Cortos Oficiales (MAYÚSCULAS)

Todos los equipos deben utilizar exactamente el mismo **`Código corto`** tanto en el nombre del archivo `.zip` (`<ALGORITMO>`) como en el campo `"algorithmCode"` del `manifest.json`, garantizando compatibilidad automática entre distintos lenguajes:

| # | Tipo de Cifrado / Categoría | Algoritmo / Método | Código corto oficial (`<ALGORITMO>`) |
| :---: | :--- | :--- | :--- |
| **1** | Simétrico por Bloques | AES-256-GCM / AES-128-GCM | **`AESGCM`** |
| **2** | Simétrico Legado | DES (56-bit) | **`DES`** |
| **3** | Simétrico Legado | Triple DES / 3DES / Triple-DES-96 | **`TRIPLEDES`** |
| **4** | Simétrico de Flujo (AEAD) | ChaCha20-Poly1305 | **`CHACHA20`** |
| **5** | Asimétrico | RSA (RSA-OAEP / RSA-PSS / Modular) | **`RSA`** |
| **6** | Asimétrico (Curva Elíptica) | ECC (ECDH / ECIES / ECDSA) | **`ECC`** |
| **7** | Acuerdo de Claves | Diffie-Hellman ($g^a \bmod p$) | **`DIFFIEHELLMAN`** |
| **8** | Clásico | Cifrado César | **`CAESAR`** |
| **9** | Clásico Polialfabético | Cifrado Vigenère | **`VIGENERE`** |
| **10** | Bajo Nivel (Ensamblador) | XOR en Registro (`WREG` / `ROL` / `ROR`) | **`XORASM`** |
| **11** | Esteganografía | Esteganografía LSB en PNG/BMP | **`LSBSTEGO`** |
| **12** | Matemático (Teoría de Números) | Euclides Extendido / Cifrado Afín | **`EUCLIDESAFFINE`** |
| **13** | Matemático (Primalidad) | Miller–Rabin + Cifrado Modular | **`MILLERRABIN`** |
| **14** | Transposición / Combinatoria | Permutación Fisher–Yates | **`FISHERYATES`** |
| **15** | Integridad (Hash) | Hash SHA-256 / SHA-512 / SHA-3 | **`HASHSHA`** |
| **16** | Autenticación | HMAC-SHA256 / HMAC-SHA512 | **`HMACSHA256`** |
| **17** | Autenticidad | Firma Digital (RSA-PSS / ECDSA) | **`DIGITALSIG`** |
| **18** | Cuántica / Poscuántica | QKD BB84 + PQC (ML-KEM / LWE) | **`QUANTUMPQC`** |
| **19** | Procesamiento de Señales | Transformada Discreta de Fourier (DFT/IDFT) | **`DFTSPECTRAL`** |
| **20** | Álgebra / Umbral | Teorema de Lagrange (Shamir en $\text{GF}(256)$) | **`LAGRANGESHAMIR`** |
| **21** | Flujo Electromecánico | Máquina / Cifrado Lorenz (SZ40/42) | **`LORENZSZ40`** |

---

## 2. Estructura Interna Obligatoria del `.ZIP`

El archivo `.zip` debe contener **exactamente 3 archivos en su raíz** (sin subcarpetas anidadas):

| Archivo | Formato | Descripción |
| :--- | :--- | :--- |
| **`datos.enc`** | Binario / Texto | Contenido cifrado (o estego-imagen / payload) generado por el algoritmo declarado. |
| **`certificado.pem`** | X.509 PEM | Certificado digital público del nodo emisor (`-----BEGIN CERTIFICATE----- ...`). |
| **`manifest.json`** | JSON UTF-8 | Metadatos técnicos, huellas de integridad y firma digital del emisor. |

### 2.1 Esquema Obligatorio de `manifest.json`
```json
{
  "version": "1.0",
  "packetId": "550e8400-e29b-41d4-a716-446655440000",
  "sourceNode": "NODO-01",
  "sourceIp": "192.168.1.14:5000",
  "timestampUtc": "2026-11-16T21:20:00Z",
  "algorithm": "AES-256-GCM",
  "payloadMode": "file",
  "originalFileName": "documento.pdf",
  "originalExtension": ".pdf",
  "originalSizeBytes": 14820,
  "encryptedSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "publicParameters": {
    "ivBase64": "...",
    "tagBase64": "...",
    "nonceHex": "..."
  },
  "certificateThumbprintSha256": "A1B2C3D4...",
  "signatureAlgorithm": "RSA-PSS-SHA256",
  "manifestSignatureBase64": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
}
```

#### Campos Críticos
* **`encryptedSha256`**: Hash `SHA-256` en minúsculas (64 caracteres hex) calculado sobre los bytes exactos de `datos.enc`.
* **`publicParameters`**: Parámetros públicos no secretos necesarios para descifrar (IV, Nonce, Tag GCM, valor `a`/`b`, etc.). **Nunca** debe incluir llaves privadas o contraseñas secretas.
* **`manifestSignatureBase64`**: Firma digital calculada con la llave privada correspondiente a `certificado.pem` sobre el contenido canónico del manifiesto (o sobre `encryptedSha256 + "|" + certificateThumbprintSha256 + "|" + timestampUtc`).

---

## 3. Protocolo de Comunicación por IP (HTTP REST)

Cada nodo expone un servidor HTTP/HTTPS en red local (`0.0.0.0:<puerto>`, recomendado `5000` o `8080`).

### 3.1 Endpoint de Estado (Descubrimiento)
* **`GET /api/status`**
* **Respuesta `200 OK`:**
  ```json
  {
    "nodeId": "NODO-01",
    "protocolVersion": "1.0",
    "status": "online",
    "acceptingPackages": true
  }
  ```

### 3.2 Endpoint de Envío / Recepción de Paquete `.ZIP`
* **`POST /api/requests/receive`**
* **`Content-Type`:** `multipart/form-data` con campo `package` (el archivo `.zip`).
* **Cabeceras opcionales recomendadas:**
  * `X-Source-Node: NODO-01`
  * `X-Packet-Id: 550e8400-e29b-41d4-a716-446655440000`
* **Límite de tamaño recomendado:** Máximo `50 MB` por paquete `.zip`.

#### Validaciones Automáticas al Recibir
1. Verificar que el cuerpo sea un `.zip` válido y no exceda el límite permitido.
2. Verificar la presencia exacta de `datos.enc`, `certificado.pem` y `manifest.json`.
3. Recalcular el `SHA-256` de `datos.enc` y compararlo con `manifest.json -> encryptedSha256`.
4. Verificar la firma digital `manifestSignatureBase64` usando la clave pública extraída de `certificado.pem`.
5. Registrar la solicitud en la bandeja de **`Solicitudes`** con estado inicial **`Pendiente`**.

#### Códigos de Respuesta HTTP
| Código | Significado | Cuándo se devuelve |
| :--- | :--- | :--- |
| **`202 Accepted`** | Solicitud recibida | El `.zip` pasó las validaciones de estructura y firma y quedó en bandeja `Pendiente` para aprobación del usuario. |
| **`400 Bad Request`** | Paquete malformado | No es un `.zip` válido o falta alguno de los 3 archivos obligatorios. |
| **`422 Unprocessable Entity`** | Integridad o firma inválida | El `SHA-256` de `datos.enc` no coincide o la firma de `certificado.pem` es falsa/corrupta. |
| **`413 Payload Too Large`** | Archivo excedido | El `.zip` supera el límite configurado. |

---

## 4. Ciclo de Vida de Aceptación, Rechazo y Consultas

```text
[Nodo Emisor] ──(POST .zip por IP)──► [Bandeja: Solicitudes (Pendiente)]
                                               │
                         ┌─────────────────────┴─────────────────────┐
                         ▼                                           ▼
                   [ Aceptar ]                                 [ Rechazar ]
                         │                                           │
                         ▼                                           ▼
        Inserta registro automáticamente                   Marca estado "Rechazada"
        en la base de datos [Consultas]                    (opcionalmente descarta .zip)
```

1. **Estado `Pendiente`:** Toda solicitud recibida por IP aparece en **`Solicitudes`** mostrando: `Origen IP`, nombre del `.zip`, `Algoritmo`, resultado de verificación (`X.509 OK` / `Inválida`) y botones **`Aceptar`** / **`Rechazar`**.
2. **Al `Aceptar`:**
   - El paquete `.zip` y sus metadatos se guardan automáticamente en la tabla principal de **`Consultas`** (base de datos local) con origen **`Recibido`**.
   - Desde **`Consultas`**, el usuario puede **descargar**, **descifrar** (si conoce la clave y el algoritmo está habilitado en `Ajustes`) o **reenviar** el `.zip` a otra IP mediante el panel lateral desplegable.
3. **Al `Rechazar`:**
   - La solicitud cambia a estado **`Rechazada`** y no se incorpora al historial de **`Consultas`**.
