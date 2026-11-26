# Estándar de Comunicación entre Nodos del Centro de Ciberseguridad — v2.0

| Campo | Valor |
| :--- | :--- |
| **Versión** | 2.0 (borrador para aprobación de los equipos) |
| **Fecha** | 2026-11-25 |
| **Reemplaza a** | Propuesta de Estándar de Intercambio `.ZIP` entre Nodos v1.0 (sin compatibilidad hacia atrás) |
| **Alcance** | Los 21 algoritmos oficiales y todos los equipos del Centro, sin importar el lenguaje (.NET, Java, Node.js, Python, etc.) |

**Propósito.** Definir todo lo que los equipos deben coordinar para que cualquier nodo pueda: (1) encontrar a los demás nodos en la LAN, (2) pedir al equipo dueño de un algoritmo que ejecute una operación y le devuelva el resultado, y (3) enviar y recibir paquetes `.zip` firmados entre bandejas.

**Lenguaje normativo.** **DEBE** / **NO DEBE** = obligatorio. **DEBERÍA** = recomendado; se puede omitir con una razón documentada. **PUEDE** = opcional.

---

## Índice

1. [Cambios respecto a v1.0](#1-cambios-respecto-a-v10)
2. [Roles y obligaciones de cada nodo](#2-roles-y-obligaciones-de-cada-nodo)
3. [Identificadores](#3-identificadores)
4. [Diccionario de equipos y algoritmos](#4-diccionario-de-equipos-y-algoritmos)
5. [Red: puertos, transporte y direccionamiento](#5-red-puertos-transporte-y-direccionamiento)
6. [Autodescubrimiento y directorio de nodos](#6-autodescubrimiento-y-directorio-de-nodos)
7. [Identidad del nodo y certificados X.509](#7-identidad-del-nodo-y-certificados-x509)
8. [Primitivas criptográficas comunes](#8-primitivas-criptográficas-comunes)
9. [Paquete `.zip`](#9-paquete-zip)
10. [API REST](#10-api-rest)
11. [Flujos de comunicación](#11-flujos-de-comunicación)
12. [Llaves de algoritmos asimétricos (`keyId`)](#12-llaves-de-algoritmos-asimétricos-keyid)
13. [Validaciones y seguridad](#13-validaciones-y-seguridad)
14. [Errores](#14-errores)
15. [Bandeja de Solicitudes y Consultas](#15-bandeja-de-solicitudes-y-consultas)
16. [Pruebas de interoperabilidad y conformidad](#16-pruebas-de-interoperabilidad-y-conformidad)
17. [Gobierno del estándar](#17-gobierno-del-estándar)
18. [Pendientes por confirmar](#18-pendientes-por-confirmar)
- [Anexo A. Ejemplos completos](#anexo-a-ejemplos-completos)
- [Anexo B. Catálogo de códigos de error](#anexo-b-catálogo-de-códigos-de-error)
- [Anexo C. Valores de referencia rápida](#anexo-c-valores-de-referencia-rápida)

---

## 1. Cambios respecto a v1.0

| # | v1.0 | v2.0 |
| :---: | :--- | :--- |
| 1 | Identificador libre (`NODO01`, `NODO-01`, `CELULA03`) | Identificador por número de equipo: `EQ01` … `EQ99`, igual en zip, manifiesto, certificado y red |
| 2 | Sin relación equipo ↔ algoritmo | Diccionario oficial (sección 4) y perfil de algoritmos publicado por cada nodo (`GET /api/algorithms`) |
| 3 | Solo bandeja manual (`/api/requests/receive`) | Además, servicio remoto síncrono: `POST /api/crypto/forward` y `POST /api/crypto/inverse` |
| 4 | Solo “cifrar/descifrar” | Pares de operación genéricos `forward` / `inverse` con significado por algoritmo (cifrar/descifrar, hash/verificar, firmar/verificar, ocultar/extraer, dividir/reconstruir) |
| 5 | Sin descubrimiento | Anuncio UDP en el puerto 5099 + escaneo HTTP de respaldo + alta manual |
| 6 | Puerto 5000 u 8080 | Puerto HTTP = 5000 + número de equipo; HTTPS opcional = 5100 + número de equipo |
| 7 | Campo `algorithm` vs `algorithmCode` ambiguo | `algorithmId` (número) + `algorithmCode` (código oficial) obligatorios |
| 8 | Firma sobre “manifiesto canónico” o cadena corta | Cadena de firma extendida única (sección 8.4) que cubre algoritmo, operación y parámetros |
| 9 | Sin forma de enviar claves | Sobre híbrido `CC-ENV-1` (RSA-OAEP + AES-256-GCM) para claves y resultados |
| 10 | Sin manejo de llaves asimétricas | `keyId` guardado por el equipo dueño del algoritmo (sección 12) |
| 11 | Exactamente 3 archivos, sin caso multiarchivo | Se mantienen 3 archivos; si hay varias partes, `datos.enc` es un zip interno |
| 12 | Errores solo con código HTTP | Cuerpo `application/problem+json` con código de error del catálogo (Anexo B) |
| 13 | Sin protección contra repetición | Ventana de ±10 min sobre `timestampUtc` y rechazo de `packetId` repetido (`409`) |

---

## 2. Roles y obligaciones de cada nodo

Cada equipo opera **un nodo**. Todo nodo **DEBE** cumplir los cuatro roles:

| Rol | Qué hace | Endpoints / mecanismos |
| :--- | :--- | :--- |
| **Emisor** | Arma un paquete `.zip` firmado y lo envía a la bandeja de otro nodo | Cliente de `POST /api/requests/receive` |
| **Receptor** | Recibe paquetes, los valida y los muestra en la bandeja *Solicitudes* para Aceptar / Rechazar | `POST /api/requests/receive` |
| **Proveedor** | Ejecuta sus algoritmos asignados cuando otro nodo se lo pide | `POST /api/crypto/forward`, `POST /api/crypto/inverse`, `GET /api/jobs/...`, `GET /api/algorithms` |
| **Solicitante** | Pide a otros nodos que ejecuten los algoritmos que no le corresponden | Cliente de `/api/crypto/*` |

Además, todo nodo **DEBE**:

- Exponer `GET /api/status` y `GET /api/certificate`.
- Emitir y escuchar el anuncio UDP de descubrimiento (sección 6).
- Mantener un directorio local de nodos con alta manual.
- Ofrecer una interfaz (web o de escritorio) para cifrar/descifrar con cualquiera de los 21 algoritmos, delegando los que no le corresponden.

---

## 3. Identificadores

| Identificador | Formato | Expresión regular | Ejemplo | Dónde se usa |
| :--- | :--- | :--- | :--- | :--- |
| `teamNumber` | Entero 1–99 | `^[1-9][0-9]?$` | `8` | Status, anuncio UDP, cálculo de puertos |
| `nodeId` | `EQ` + número de equipo a 2 dígitos | `^EQ[0-9]{2}$` | `EQ08` | Nombre del zip, manifiesto, CN del certificado, encabezados |
| `algorithmId` | Entero 1–21 (número de la tabla oficial) | `^([1-9]\|1[0-9]\|2[01])$` | `15` | Manifiesto, perfiles |
| `algorithmCode` | Código oficial en MAYÚSCULAS, sin guiones | ver sección 4 | `HASHSHA` | Nombre del zip, manifiesto, rutas |
| `operation` | `forward` o `inverse` | `^(forward\|inverse)$` | `forward` | Manifiesto, peticiones |
| `packetId` | UUID v4 en minúsculas | `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$` | `550e8400-e29b-41d4-a716-446655440000` | Manifiesto (único por paquete) |
| `requestId` | UUID v4 en minúsculas | igual que `packetId` | `0b8d…` | Peticiones `/api/crypto/*` |
| `jobId` | UUID v4 en minúsculas | igual que `packetId` | `7c1e…` | Operaciones asíncronas |
| `keyId` | `<nodeId>-KEY-<UUID v4>` | `^EQ[0-9]{2}-KEY-[0-9a-f-]{36}$` | `EQ03-KEY-1f0c…` | Llaves asimétricas guardadas por el dueño |
| `timestampUtc` | ISO 8601 UTC, segundos, sufijo `Z` | `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$` | `2026-11-25T15:47:00Z` | Manifiesto, anuncio, peticiones |
| Huella de certificado | SHA-256 del certificado en DER, hex **MAYÚSCULAS** sin separadores (64 caracteres) | `^[0-9A-F]{64}$` | `A1B2…` | Manifiesto, status, anuncio, sobres |
| Hash de contenido | SHA-256 hex **minúsculas** (64 caracteres) | `^[0-9a-f]{64}$` | `9f86d081…` | `encryptedSha256`, `publicParametersSha256` |

Reglas:

- Los identificadores **DEBEN** compararse de forma exacta (sensible a mayúsculas).
- Un nodo **NO DEBE** usar un `nodeId` distinto al de su número de equipo.

---

## 4. Diccionario de equipos y algoritmos

### 4.1 Asignación oficial

| # | `algorithmCode` | Algoritmo | Categoría | Equipo | `nodeId` | `forward` | `inverse` | Tipo de llave |
| :---: | :--- | :--- | :--- | :---: | :---: | :--- | :--- | :--- |
| 1 | `AESGCM` | AES-256-GCM / AES-128-GCM | Simétrico por bloques | 1 | `EQ01` | cifrar | descifrar | Secreta |
| 2 | `DES` | DES 56-bit | Simétrico legado | 1 | `EQ01` | cifrar | descifrar | Secreta |
| 3 | `TRIPLEDES` | Triple DES / 3DES | Simétrico legado | 2 | `EQ02` | cifrar | descifrar | Secreta |
| 4 | `CHACHA20` | ChaCha20-Poly1305 | Simétrico de flujo (AEAD) | 2 | `EQ02` | cifrar | descifrar | Secreta |
| 5 | `RSA` | RSA-OAEP / RSA-PSS | Asimétrico | 3 | `EQ03` | cifrar | descifrar | `keyId` |
| 6 | `ECC` | ECDH / ECIES / ECDSA | Asimétrico (curva elíptica) | 3 | `EQ03` | cifrar | descifrar | `keyId` |
| 7 | `DIFFIEHELLMAN` | Diffie-Hellman | Acuerdo de claves | 4 ⚠ | `EQ04` | cifrar | descifrar | `keyId` |
| 8 | `CAESAR` | Cifrado César | Clásico | 4 ⚠ | `EQ04` | cifrar | descifrar | Secreta |
| 9 | `VIGENERE` | Cifrado Vigenère | Clásico polialfabético | 5 | `EQ05` | cifrar | descifrar | Secreta |
| 10 | `XORASM` | XOR en registro (`WREG`/`ROL`/`ROR`) | Bajo nivel | 5 | `EQ05` | cifrar | descifrar | Secreta |
| 11 | `LSBSTEGO` | Esteganografía LSB en PNG/BMP | Esteganografía | 6 | `EQ06` | ocultar | extraer | Secreta opcional |
| 12 | `EUCLIDESAFFINE` | Euclides extendido / Afín | Teoría de números | 6 | `EQ06` | cifrar | descifrar | Secreta |
| 13 | `MILLERRABIN` | Miller–Rabin + cifrado modular | Primalidad | 7 | `EQ07` | cifrar | descifrar | `keyId` |
| 14 | `FISHERYATES` | Permutación Fisher–Yates | Transposición | 7 | `EQ07` | permutar | restaurar | Secreta |
| 15 | `HASHSHA` | SHA-256 / SHA-512 / SHA-3 | Integridad | 8 | `EQ08` | calcular hash | verificar | Ninguna |
| 16 | `HMACSHA256` | HMAC-SHA256 / HMAC-SHA512 | Autenticación | 8 | `EQ08` | calcular MAC | verificar | Secreta |
| 17 | `DIGITALSIG` | Firma digital RSA-PSS / ECDSA | Autenticidad | — | — | firmar | verificar | `keyId` |
| 18 | `QUANTUMPQC` | QKD BB84 + PQC (ML-KEM / LWE) | Poscuántica | — | — | cifrar | descifrar | `keyId` |
| 19 | `DFTSPECTRAL` | Transformada discreta de Fourier | Señales | — | — | transformar | invertir | Secreta opcional |
| 20 | `LAGRANGESHAMIR` | Shamir en GF(256) | Umbral | — | — | dividir | reconstruir | Ninguna (las partes son el secreto) |
| 21 | `LORENZSZ40` | Lorenz SZ40/42 | Flujo electromecánico | — | — | cifrar | descifrar | Secreta |

⚠ El Equipo 4 no reportó asignación; se asume 7 y 8 por continuidad hasta que lo confirme.
— Los algoritmos 17 a 21 están **reservados sin dueño**. Un nodo **PUEDE** implementarlos y anunciarlos (sección 4.4).

### 4.2 Parámetros por algoritmo

- **Secretos** viajan solo dentro de un sobre `CC-ENV-1` (sección 8.3), nunca en `manifest.json`.
- **Públicos** van en `publicParameters` del manifiesto.

Esta tabla fija el **mínimo**. El equipo dueño **DEBE** confirmar o completar los nombres exactos en su perfil (`GET /api/algorithms`) antes de la fecha de congelamiento (sección 17).

Todos los valores binarios se codifican en Base64 estándar (RFC 4648, con relleno `=`). Todos los valores en `publicParameters` son **cadenas** (ver 8.5).

| Código | Secretos (sobre `CC-ENV-1`) | `publicParameters` mínimos | Notas |
| :--- | :--- | :--- | :--- |
| `AESGCM` | `key` (16 o 32 bytes) | `keySizeBits`, `nonceBase64` (12 B), `tagBase64` (16 B) | AAD = `packetId` en UTF-8 |
| `DES` | `key` (8 bytes) | `mode`=`CBC`, `padding`=`PKCS7`, `ivBase64` (8 B) | Solo con fines didácticos |
| `TRIPLEDES` | `key` (24 bytes) | `mode`=`CBC`, `padding`=`PKCS7`, `ivBase64` (8 B) | |
| `CHACHA20` | `key` (32 bytes) | `nonceBase64` (12 B), `tagBase64` (16 B) | AAD = `packetId` en UTF-8 |
| `RSA` | — | `keyId`, `scheme`=`RSA-OAEP-SHA256+A256GCM`, `wrappedKeyBase64`, `nonceBase64`, `tagBase64` | Híbrido: RSA no cifra archivos grandes directamente |
| `ECC` | — | `keyId`, `curve`=`P-256`, `scheme`=`ECIES`, `ephemeralPublicKeyBase64`, `nonceBase64`, `tagBase64` | |
| `DIFFIEHELLMAN` | — | `keyId`, `pBase64`, `g`, `publicValueBase64`, `kdf`=`SHA-256`, `nonceBase64`, `tagBase64` | Clave derivada cifra con AES-GCM |
| `CAESAR` | `shift` (entero) | `alphabet` (`A-Z` o `BYTE`) | `BYTE` = desplazamiento módulo 256 para archivos |
| `VIGENERE` | `key` (texto) | `alphabet` (`A-Z` o `BYTE`) | |
| `XORASM` | `key` (1–8 bytes) | `rotation` (`ROL`/`ROR`), `rotationBits` | |
| `LSBSTEGO` | `password` (opcional) | `imageFormat` (`PNG`/`BMP`), `bitsPerChannel`, `channels`, `payloadLengthBytes` | `forward` requiere la parte `cover` (imagen portadora); `datos.enc` = imagen resultante |
| `EUCLIDESAFFINE` | `a`, `b` (con mcd(a, m) = 1) | `modulus` (`26` o `256`) | |
| `MILLERRABIN` | — | `keyId`, `modulusBase64`, `exponent`, `rounds` | |
| `FISHERYATES` | `seed` | `blockSize`, `prng` | El PRNG **DEBE** documentarse para ser reproducible |
| `HASHSHA` | — | `hashAlgorithm` (`SHA-256`/`SHA-512`/`SHA3-256`), `digestHex` | `datos.enc` = archivo original |
| `HMACSHA256` | `key` (≥ 32 bytes) | `macAlgorithm` (`HMAC-SHA256`/`HMAC-SHA512`), `macHex` | `datos.enc` = archivo original |
| `DIGITALSIG` | — | `keyId`, `signatureScheme`, `signatureBase64` | `datos.enc` = archivo original |
| `QUANTUMPQC` | — | `keyId`, `kem`, `kemCiphertextBase64`, `nonceBase64`, `tagBase64` | |
| `DFTSPECTRAL` | `key` (opcional) | `n`, `scale`, `sampleFormat` | |
| `LAGRANGESHAMIR` | — | `threshold` (k), `shares` (n), `field`=`GF(256)` | `datos.enc` = zip interno con las n partes |
| `LORENZSZ40` | `wheelStarts` | `wheelPatternId` | `forward` e `inverse` son la misma operación |

### 4.3 Significado de `forward` e `inverse` en algoritmos no reversibles

| Código | `forward` produce | `inverse` recibe | `inverse` devuelve |
| :--- | :--- | :--- | :--- |
| `HASHSHA` | `datos.enc` = original; `digestHex` en `publicParameters` | El paquete | Original + veredicto `valid` |
| `HMACSHA256` | `datos.enc` = original; `macHex` en `publicParameters` | El paquete + `key` en sobre | Original + veredicto `valid` |
| `DIGITALSIG` | `datos.enc` = original; `signatureBase64` en `publicParameters` | El paquete | Original + veredicto `valid` |
| `LSBSTEGO` | Imagen con el mensaje oculto | El paquete (+ `password` si aplica) | Mensaje extraído |
| `LAGRANGESHAMIR` | Zip interno con n partes | Paquete con ≥ k partes en `datos.enc` | Secreto reconstruido |

### 4.4 Algoritmos reservados y proveedores adicionales

- Un nodo que implemente un algoritmo reservado (17–21) **DEBE** incluirlo en su anuncio UDP, en `GET /api/status` y en `GET /api/algorithms`.
- Si dos nodos anuncian el mismo algoritmo, el solicitante **DEBE** preferir al dueño de la tabla 4.1. Para los reservados, gana el `teamNumber` menor salvo que el usuario elija otro.
- El primer equipo que anuncie un algoritmo reservado **DEBERÍA** notificarlo para actualizar la tabla 4.1 en la siguiente versión menor.

---

## 5. Red: puertos, transporte y direccionamiento

### 5.1 Puertos

| Servicio | Protocolo | Puerto | Equipo 8 | Obligatorio |
| :--- | :--- | :--- | :---: | :---: |
| API REST | HTTP | `5000 + teamNumber` | `5008` | Sí |
| API REST | HTTPS | `5100 + teamNumber` | `5108` | No |
| Anuncio de descubrimiento | UDP | `5099` (común a todos) | `5099` | Sí |

- El servidor **DEBE** escuchar en `0.0.0.0` (todas las interfaces), no solo en `localhost`.
- Cada equipo **DEBE** abrir estos puertos en el firewall del sistema operativo y documentarlo en su manual de instalación.
- El esquema permite correr varios nodos en una sola máquina para pruebas.

### 5.2 Transporte

- HTTP es la base obligatoria. Todos los nodos **DEBEN** aceptar peticiones HTTP.
- HTTPS es opcional. Si un nodo lo ofrece, lo anuncia con `httpsPort` (≠ `null`) y **DEBE** usar el mismo certificado X.509 de su identidad (sección 7).
- Si ambos nodos ofrecen HTTPS, el solicitante **DEBERÍA** usarlo y **DEBE** validar que la huella del certificado TLS coincida con la huella fijada en su directorio. No se valida cadena de confianza (los certificados son autofirmados).
- La confidencialidad **no depende** del transporte: claves y resultados sensibles siempre viajan dentro de sobres `CC-ENV-1`.

### 5.3 Direccionamiento

- Las IP pueden ser asignadas por DHCP. El nodo **DEBE** anunciar su IP actual en cada anuncio UDP.
- Si la máquina tiene varias interfaces, el nodo **DEBE** anunciar la IP de la interfaz por la que sale el anuncio.
- Se **DEBERÍA** usar una red local dedicada (router o hotspot propio). Las redes escolares suelen aislar a los clientes y bloquear broadcast (ver sección 18).
- Todos los nodos **DEBERÍAN** sincronizar su reloj con NTP; la ventana de tiempo es de ±10 min (sección 13).

---

## 6. Autodescubrimiento y directorio de nodos

### 6.1 Anuncio UDP (mecanismo principal)

- Cada nodo **DEBE** enviar un anuncio al iniciar y después cada **30 s**.
- Destinos: `255.255.255.255:5099` y la dirección de broadcast de su subred (ej. `192.168.1.255:5099`).
- Contenido: un objeto JSON en UTF-8, ≤ 1024 bytes, sin compresión.
- Al apagarse, el nodo **DEBERÍA** enviar un último anuncio con `"status": "offline"`.

```json
{
  "type": "CC-BEACON",
  "protocolVersion": "2.0",
  "nodeId": "EQ08",
  "teamNumber": 8,
  "ip": "192.168.1.14",
  "httpPort": 5008,
  "httpsPort": null,
  "status": "online",
  "algorithms": ["HASHSHA", "HMACSHA256"],
  "certificateThumbprintSha256": "A1B2C3D4E5F6...",
  "timestampUtc": "2026-11-25T15:47:00Z"
}
```

- Al recibir un anuncio, el nodo **DEBE** ignorar los propios y los que tengan `type` o `protocolVersion` distintos.
- Un anuncio **no es confiable por sí mismo**: antes de usar el nodo se **DEBE** confirmar con `GET /api/status` y `GET /api/certificate` (6.3).
- Un nodo se marca `offline` si no se recibe anuncio ni responde `GET /api/status` en **90 s**.

### 6.2 Escaneo HTTP (respaldo)

Para redes que bloquean broadcast:

- El nodo **DEBE** ofrecer un botón o comando “Buscar nodos” que recorra su subred /24 en los puertos `5001`–`5020` con `GET /api/status`.
- Tiempo límite por intento: 500 ms. Paralelismo máximo: 64 conexiones.
- El escaneo **NO DEBE** ejecutarse en ciclo automático más de una vez cada 5 min.

### 6.3 Alta y confianza

1. Fuentes de alta: anuncio UDP, escaneo HTTP o **alta manual** (IP + puerto). La alta manual **DEBE** existir siempre.
2. El nodo consulta `GET /api/status` y `GET /api/certificate`.
3. Verifica que el `nodeId` coincida con el CN del certificado y que la huella coincida con la anunciada.
4. **Confianza en el primer uso (TOFU):** la interfaz muestra la huella y el usuario la confirma. A partir de ese momento la huella queda **fijada**.
5. Si un nodo conocido presenta una huella distinta, **NO DEBE** usarse hasta que el usuario lo acepte de nuevo. La interfaz **DEBE** alertar del cambio.

### 6.4 Datos mínimos del directorio local

| Campo | Descripción |
| :--- | :--- |
| `nodeId`, `teamNumber` | Identidad |
| `ip`, `httpPort`, `httpsPort` | Ubicación actual |
| `pinnedThumbprintSha256` | Huella confirmada por el usuario |
| `algorithms` | Códigos que anuncia |
| `source` | `beacon`, `scan` o `manual` |
| `status`, `lastSeenUtc` | `online` / `offline` y última vez visto |

---

## 7. Identidad del nodo y certificados X.509

| Atributo | Valor obligatorio |
| :--- | :--- |
| Tipo de llave | RSA-2048 |
| Algoritmo de firma del certificado | `sha256WithRSAEncryption` |
| Sujeto | `CN=<nodeId>, OU=Equipo <NN>, O=Centro de Ciberseguridad, C=MX` |
| Emisor | Igual al sujeto (autofirmado) |
| Vigencia | 365 días desde su generación |
| Número de serie | Aleatorio, ≥ 64 bits |
| Uso de llave | `digitalSignature`, `keyEncipherment` |
| Formato de intercambio | PEM (`-----BEGIN CERTIFICATE-----`), un solo certificado |
| Huella | SHA-256 del DER, hex MAYÚSCULAS |

- La llave privada **NO DEBE** salir del nodo ni guardarse en claro en la base de datos. Se **DEBERÍA** proteger con el almacén del sistema operativo o cifrarse en disco.
- Regenerar el certificado cambia la huella; los demás nodos verán la alerta de 6.3 y deberán volver a confirmar.
- Esta llave de **identidad** es distinta de las llaves de algoritmo (`keyId`, sección 12).

---

## 8. Primitivas criptográficas comunes

Todos los nodos **DEBEN** implementar exactamente estas primitivas, sin importar sus algoritmos asignados.

### 8.1 Hash de contenido

SHA-256 sobre los bytes exactos; resultado en hex minúsculas.

### 8.2 Firma

- Algoritmo: **RSA-PSS** con SHA-256, MGF1-SHA256, sal de 32 bytes.
- Nombre en el manifiesto: `"signatureAlgorithm": "RSA-PSS-SHA256"`.
- Se firman los bytes UTF-8 de la **cadena de firma** (8.4); la librería calcula el SHA-256 internamente.
- Resultado en Base64.

### 8.3 Sobre híbrido `CC-ENV-1`

Se usa para (a) enviar secretos al proveedor y (b) devolver resultados al solicitante.

1. Generar una clave aleatoria `CEK` de 32 bytes y un `nonce` de 12 bytes.
2. Cifrar el contenido con **AES-256-GCM** (etiqueta de 16 bytes). AAD = UTF-8 del `requestId` (o del `packetId` para resultados).
3. Envolver `CEK` con **RSA-OAEP** (SHA-256, MGF1-SHA256, sin etiqueta) usando la llave pública del certificado del **destinatario**.

```json
{
  "envelope": "CC-ENV-1",
  "recipientNode": "EQ08",
  "recipientThumbprintSha256": "A1B2C3D4E5F6...",
  "wrappedKeyBase64": "...",
  "nonceBase64": "...",
  "tagBase64": "...",
  "ciphertextBase64": "..."
}
```

- Para secretos, el contenido cifrado es un JSON UTF-8 con los campos secretos de la tabla 4.2, todos como cadenas. Ejemplo: `{"key":"q83vEj...=="}` o `{"shift":"3"}`.
- Para resultados, el texto cifrado va en el archivo `resultado.enc` y el sobre (sin `ciphertextBase64`) va en `resultEnvelope` del manifiesto.
- El destinatario **DEBE** rechazar el sobre si `recipientThumbprintSha256` no es su huella (`E-ENV-RECIPIENT`).

### 8.4 Cadena de firma del manifiesto

Campos unidos con `|` (barra vertical), sin espacios, en este orden exacto:

```text
version|packetType|packetId|sourceNode|producerNode|algorithmCode|operation|timestampUtc|encryptedSha256|publicParametersSha256|certificateThumbprintSha256
```

Ejemplo:

```text
2.0|package|550e8400-e29b-41d4-a716-446655440000|EQ08|EQ08|HASHSHA|forward|2026-11-25T15:47:00Z|9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08|3b2c...e1|A1B2C3D4E5F6...
```

### 8.5 Hash canónico de `publicParameters`

JSON se serializa distinto en cada lenguaje, por eso no se hashea el JSON. En su lugar:

1. `publicParameters` **DEBE** ser un objeto plano (sin objetos ni arreglos anidados) con valores **cadena**.
2. Ordenar las llaves por orden ordinal de bytes UTF-8 (ascendente).
3. Formar una línea `llave=valor` por par.
4. Unir las líneas con `\n` (LF), sin salto final.
5. `publicParametersSha256` = SHA-256 de esos bytes UTF-8, hex minúsculas.
6. Si `publicParameters` está vacío, se hashea la cadena vacía (`e3b0c442...b855`).

Ejemplo: `{"hashAlgorithm":"SHA-256","digestHex":"ab12"}` → `digestHex=ab12\nhashAlgorithm=SHA-256`.

---

## 9. Paquete `.zip`

### 9.1 Tipos de paquete

| `packetType` | Lo genera | Contenido |
| :--- | :--- | :--- |
| `package` | Proveedor (respuesta de `forward`) o emisor (envío a bandeja) | `datos.enc`, `certificado.pem`, `manifest.json` |
| `result` | Proveedor (respuesta de `inverse`) | `resultado.enc`, `certificado.pem`, `manifest.json` |

### 9.2 Nomenclatura

```text
package: <NODEID>_<ALGORITMO>_<YYYYMMDD_HHMMSS>_<SHA8>.zip
result:  RES_<NODEID>_<ALGORITMO>_<YYYYMMDD_HHMMSS>_<SHA8>.zip
```

- `<NODEID>` = `sourceNode` del manifiesto (ej. `EQ08`).
- `<ALGORITMO>` = `algorithmCode`.
- `<YYYYMMDD_HHMMSS>` = el mismo instante que `timestampUtc`, en UTC.
- `<SHA8>` = primeros 8 caracteres de `encryptedSha256` en **MAYÚSCULAS**.
- Ejemplo: `EQ08_HASHSHA_20261125_154700_9F86D081.zip`.
- El nombre es informativo: el receptor **DEBE** validar contra el manifiesto, no contra el nombre.

### 9.3 Estructura

- Exactamente **3 archivos** en la raíz, con estos nombres en minúsculas. Sin carpetas, sin archivos ocultos, sin rutas con `/`, `\` o `..`.
- Compresión `deflate` o `store`. El zip **NO DEBE** estar protegido con contraseña.
- Nombres de entrada en UTF-8.

### 9.4 Contenido multiarchivo

Cuando una operación produce o requiere varias partes (ej. `LAGRANGESHAMIR`):

- `datos.enc` **es a su vez un zip** con entradas planas `part-01.bin`, `part-02.bin`, …
- El manifiesto lleva `"payloadMode": "multipart"` y el arreglo `parts` con nombre, tamaño y SHA-256 de cada parte.
- El zip interno sigue las mismas reglas de 9.3, con máximo 64 entradas.

### 9.5 `manifest.json` (v2.0)

| Campo | Tipo | Obligatorio | Descripción |
| :--- | :--- | :---: | :--- |
| `version` | cadena | Sí | `"2.0"` |
| `packetType` | cadena | Sí | `package` o `result` |
| `packetId` | UUID | Sí | Único por paquete |
| `requestId` | UUID \| null | Sí | Petición `/api/crypto/*` que lo originó; `null` si no aplica |
| `sourceNode` | `nodeId` | Sí | Quien firma y envía este paquete |
| `sourceTeam` | entero | Sí | Número de equipo de `sourceNode` |
| `sourceIp` | cadena | Sí | `IP:puerto` del emisor (ej. `192.168.1.14:5008`) |
| `producerNode` | `nodeId` | Sí | Quien ejecutó el algoritmo (puede ser distinto de `sourceNode` al reenviar) |
| `timestampUtc` | cadena | Sí | Momento del empaquetado |
| `algorithmId` | entero | Sí | Número oficial 1–21 |
| `algorithmCode` | cadena | Sí | Código oficial |
| `algorithmName` | cadena | Sí | Nombre descriptivo (ej. `"SHA-256"`, `"AES-256-GCM"`) |
| `operation` | cadena | Sí | `forward` o `inverse` |
| `operationName` | cadena | Sí | Significado legible (ej. `"calcular hash"`, `"verificar"`) |
| `payloadMode` | cadena | Sí | `text`, `file`, `image` o `multipart` |
| `originalFileName` | cadena | Sí | Nombre del archivo original (`mensaje.txt` si es texto) |
| `originalExtension` | cadena | Sí | Con punto (ej. `.pdf`) |
| `originalSizeBytes` | entero | Sí | Tamaño antes de procesar |
| `contentType` | cadena | Sí | Tipo MIME del original |
| `encryptedSha256` | hex | Sí | SHA-256 de `datos.enc` (o de `resultado.enc`) |
| `encryptedSizeBytes` | entero | Sí | Tamaño de `datos.enc` / `resultado.enc` |
| `parts` | arreglo \| null | Sí | Solo en `multipart`: `[{ "name", "sizeBytes", "sha256" }]` |
| `keyRef` | objeto \| null | Sí | `{ "keyId", "ownerNode" }` para algoritmos con `keyId` |
| `publicParameters` | objeto plano de cadenas | Sí | Ver tabla 4.2; nunca secretos |
| `publicParametersSha256` | hex | Sí | Ver 8.5 |
| `verification` | objeto \| null | Solo en `result` | `{ "valid": true\|false, "detail": "..." }` para hash, MAC y firma |
| `resultEnvelope` | objeto \| null | Solo en `result` | Sobre `CC-ENV-1` sin `ciphertextBase64` (sección 8.3) |
| `certificateThumbprintSha256` | hex | Sí | Huella de `certificado.pem` |
| `signatureAlgorithm` | cadena | Sí | `"RSA-PSS-SHA256"` |
| `manifestSignatureBase64` | Base64 | Sí | Firma de la cadena 8.4 |

Reglas:

- Campos desconocidos **DEBEN** ignorarse (permite extensiones menores).
- `manifest.json` **NO DEBE** contener llaves privadas, contraseñas ni claves simétricas.

### 9.6 Reenvío

Un nodo que reenvía un paquete producido por otro **DEBE**:

1. Conservar `datos.enc`, `publicParameters`, `keyRef`, `producerNode` y `algorithmCode` sin cambios.
2. Generar nuevo `packetId` y `timestampUtc`.
3. Poner su propio `nodeId` en `sourceNode` y su certificado en `certificado.pem`.
4. Volver a firmar con su llave de identidad.

---

## 10. API REST

### 10.1 Convenciones generales

- Prefijo: `/api`. Sin autenticación de usuario; la autenticación entre nodos es por firma y certificado.
- JSON en UTF-8, nombres en `camelCase`.
- Encabezados en todas las peticiones salientes:
  - `X-CC-Node: EQ08`
  - `X-CC-Protocol: 2.0`
  - `X-CC-Request-Id: <requestId o packetId>`
- Errores: `application/problem+json` (sección 14).
- Tamaño máximo de cuerpo: 50 MB.

### 10.2 Resumen de endpoints

| Método y ruta | Rol | Petición | Respuesta exitosa |
| :--- | :--- | :--- | :--- |
| `GET /api/status` | Todos | — | `200` JSON de estado |
| `GET /api/certificate` | Todos | — | `200` `application/x-pem-file` |
| `GET /api/algorithms` | Proveedor | — | `200` JSON con perfiles de sus algoritmos |
| `POST /api/requests/receive` | Receptor | `multipart/form-data`: `package` | `202` JSON |
| `POST /api/crypto/forward` | Proveedor | `multipart/form-data` (10.6) | `200` `application/zip` (`package`) o `202` con `jobId` |
| `POST /api/crypto/inverse` | Proveedor | `multipart/form-data` (10.6) | `200` `application/zip` (`result`) o `202` con `jobId` |
| `GET /api/jobs/{jobId}` | Proveedor | — | `200` JSON de estado del trabajo |
| `GET /api/jobs/{jobId}/result` | Proveedor | — | `200` `application/zip` |
| `GET /api/keys/{keyId}` | Proveedor | — | `200` JSON con la llave **pública** del `keyId` (opcional) |

### 10.3 `GET /api/status`

```json
{
  "nodeId": "EQ08",
  "teamNumber": 8,
  "protocolVersion": "2.0",
  "status": "online",
  "acceptingPackages": true,
  "httpPort": 5008,
  "httpsPort": null,
  "algorithms": [
    { "algorithmId": 15, "algorithmCode": "HASHSHA" },
    { "algorithmId": 16, "algorithmCode": "HMACSHA256" }
  ],
  "certificateThumbprintSha256": "A1B2C3D4E5F6...",
  "serverTimeUtc": "2026-11-25T15:47:00Z"
}
```

### 10.4 `GET /api/algorithms` (perfil)

Cada proveedor publica cómo usar sus algoritmos. Las interfaces de los demás equipos **DEBERÍAN** construir el formulario de parámetros a partir de este perfil.

```json
{
  "nodeId": "EQ08",
  "algorithms": [
    {
      "algorithmId": 16,
      "algorithmCode": "HMACSHA256",
      "variants": ["HMAC-SHA256", "HMAC-SHA512"],
      "operations": {
        "forward": { "name": "calcular MAC", "inputs": ["payload"] },
        "inverse": { "name": "verificar", "inputs": ["package"] }
      },
      "secretParameters": [
        { "name": "key", "type": "base64", "minBytes": 32, "requiredFor": ["forward", "inverse"] }
      ],
      "options": [
        { "name": "macAlgorithm", "type": "enum", "values": ["HMAC-SHA256", "HMAC-SHA512"], "default": "HMAC-SHA256" }
      ],
      "publicParameters": ["macAlgorithm", "macHex"],
      "payloadModes": ["text", "file", "image"],
      "maxPayloadBytes": 52428800
    }
  ]
}
```

### 10.5 `POST /api/requests/receive`

- `Content-Type: multipart/form-data`, campo `package` con el `.zip`.
- Respuesta `202 Accepted`:

```json
{ "packetId": "550e8400-...", "status": "Pendiente", "receivedAtUtc": "2026-11-25T15:47:03Z" }
```

### 10.6 `POST /api/crypto/forward` y `POST /api/crypto/inverse`

**Partes del `multipart/form-data`:**

| Parte | Tipo | `forward` | `inverse` | Descripción |
| :--- | :--- | :---: | :---: | :--- |
| `request` | `application/json` | Sí | Sí | Objeto de petición (abajo) |
| `requestSignature` | texto | Sí | Sí | Base64 de la firma RSA-PSS-SHA256 sobre los **bytes exactos** de la parte `request` |
| `requesterCertificate` | PEM | Sí | Sí | Certificado del solicitante |
| `payload` | binario | Sí | — | Archivo, texto (UTF-8) o imagen a procesar |
| `cover` | binario | Solo `LSBSTEGO` | — | Imagen portadora PNG/BMP |
| `package` | `application/zip` | — | Sí | Paquete `package` a invertir |

**Objeto `request`:**

```json
{
  "version": "2.0",
  "requestId": "0b8d6c1e-2f3a-4b5c-8d9e-0a1b2c3d4e5f",
  "requesterNode": "EQ08",
  "targetNode": "EQ01",
  "timestampUtc": "2026-11-25T15:47:00Z",
  "algorithmCode": "AESGCM",
  "operation": "forward",
  "payloadMode": "file",
  "originalFileName": "documento.pdf",
  "options": { "keySizeBits": "256" },
  "keyId": null,
  "secrets": {
    "envelope": "CC-ENV-1",
    "recipientNode": "EQ01",
    "recipientThumbprintSha256": "C3D4...",
    "wrappedKeyBase64": "...",
    "nonceBase64": "...",
    "tagBase64": "...",
    "ciphertextBase64": "..."
  }
}
```

- `options` = parámetros públicos que el usuario elige (todos cadenas).
- `secrets` = sobre `CC-ENV-1` cifrado para el **proveedor**; `null` si el algoritmo no requiere secretos.
- `keyId` = solo para algoritmos con llave guardada por el dueño (sección 12).

**Comportamiento del proveedor:**

1. Validar la petición (sección 13.2).
2. Ejecutar la operación con tope de **30 s**.
3. Si termina a tiempo:
   - `forward` → `200` con un `.zip` tipo `package` (`sourceNode` = `producerNode` = proveedor).
   - `inverse` → `200` con un `.zip` tipo `result`, cuyo `resultado.enc` va cifrado con `CC-ENV-1` para el certificado del **solicitante**.
4. Si no termina en 30 s → `202` con:

```json
{ "jobId": "7c1e...", "statusUrl": "/api/jobs/7c1e...", "retryAfterSeconds": 5 }
```

5. El proveedor **DEBE** descartar los secretos de memoria al terminar y **NO DEBE** registrarlos en bitácoras.

### 10.7 `GET /api/jobs/{jobId}`

```json
{ "jobId": "7c1e...", "state": "running", "progressPercent": 40, "resultUrl": null, "error": null }
```

- `state`: `queued`, `running`, `done`, `failed`.
- Cuando `state` = `done`, `resultUrl` = `/api/jobs/{jobId}/result`.
- Solo el `requesterNode` original **PUEDE** descargar el resultado: la petición debe traer `X-CC-Node` igual al solicitante, y el resultado ya va cifrado para él.
- El proveedor **DEBE** conservar resultados al menos **1 h**.

---

## 11. Flujos de comunicación

### 11.1 Descubrimiento

```text
[EQ08] ──UDP CC-BEACON 5099──► (broadcast LAN)
[EQ01] recibe ──GET /api/status──► [EQ08]
       ──GET /api/certificate──► [EQ08]
       usuario confirma huella → EQ08 queda fijado en el directorio de EQ01
```

### 11.2 Cifrar con un algoritmo de otro equipo (`forward` delegado)

```text
Usuario EQ08 elige AESGCM
EQ08 busca en el directorio → dueño EQ01 (online, huella fijada)
EQ08 cifra la clave del usuario en CC-ENV-1 para EQ01
EQ08 ──POST /api/crypto/forward──► EQ01
EQ01 valida, cifra, firma ──200 application/zip (package)──► EQ08
EQ08 verifica firma de EQ01 y guarda en Consultas (origen: Generado)
```

### 11.3 Enviar el resultado a la bandeja de un tercero

```text
EQ08 reempaqueta (9.6): sourceNode=EQ08, producerNode=EQ01, re-firma
EQ08 ──POST /api/requests/receive──► EQ05
EQ05 valida → Solicitudes (Pendiente) → usuario Acepta → Consultas (origen: Recibido)
```

### 11.4 Descifrar un paquete recibido (`inverse` delegado)

```text
Usuario EQ05 abre el paquete en Consultas; algoritmo AESGCM → dueño EQ01
Usuario EQ05 captura la clave (compartida fuera de banda)
EQ05 cifra la clave en CC-ENV-1 para EQ01
EQ05 ──POST /api/crypto/inverse (package)──► EQ01
EQ01 descifra, cifra el resultado con CC-ENV-1 para EQ05 ──200 application/zip (result)──► EQ05
EQ05 abre el sobre con su llave privada y entrega el original al usuario
```

### 11.5 Algoritmo propio

Si el algoritmo pertenece al mismo nodo, la operación se ejecuta localmente. El paquete resultante **DEBE** ser idéntico en formato al que produciría una llamada remota.

### 11.6 Dueño fuera de línea

- El solicitante **DEBE** mostrar el algoritmo como “no disponible” y el motivo.
- Alternativa manual: enviar el paquete a la bandeja del dueño (`/api/requests/receive`) para que lo procese a mano y devuelva otro paquete.

---

## 12. Llaves de algoritmos asimétricos (`keyId`)

Aplica a `RSA`, `ECC`, `DIFFIEHELLMAN`, `MILLERRABIN`, `DIGITALSIG` y `QUANTUMPQC`.

1. En `forward` sin `keyId`, el dueño **genera** un par de llaves, guarda la privada y crea un `keyId` (`EQ03-KEY-<uuid>`).
2. En `forward` con `keyId`, el dueño reutiliza esa llave.
3. El `keyId` y el `ownerNode` van en `keyRef` del manifiesto y en `publicParameters.keyId`.
4. En `inverse`, el solicitante envía el paquete; el dueño toma el `keyId` del manifiesto.
5. Cualquier nodo con huella fijada **PUEDE** usar un `keyId` (cualquier receptor del paquete puede descifrarlo). El dueño **PUEDE** restringirlo con `options.allowedNodes` (lista de `nodeId` separada por comas) en el `forward`.
6. El dueño **DEBE** conservar las llaves al menos hasta el cierre del semestre y **NO DEBE** exponer la privada.
7. `GET /api/keys/{keyId}` (opcional) devuelve solo la llave pública y metadatos.
8. `keyId` desconocido → `404` con `E-KEY-NOT-FOUND`.

---

## 13. Validaciones y seguridad

### 13.1 Al recibir un paquete (bandeja o `inverse`)

En este orden; se detiene en el primer fallo:

| # | Validación | Error |
| :---: | :--- | :--- |
| 1 | Cuerpo ≤ 50 MB | `413` `E-SIZE` |
| 2 | Es un zip válido | `400` `E-ZIP-INVALID` |
| 3 | Exactamente 3 entradas con los nombres de 9.3; sin rutas ni carpetas | `400` `E-ZIP-STRUCTURE` |
| 4 | Tamaño descomprimido ≤ 200 MB y razón de compresión ≤ 100:1 | `400` `E-ZIP-BOMB` |
| 5 | `manifest.json` es JSON válido con todos los campos obligatorios y formatos de la sección 3 | `400` `E-MANIFEST` |
| 6 | `version` = `2.0` | `400` `E-VERSION` |
| 7 | `algorithmId` y `algorithmCode` coinciden con la tabla 4.1 | `400` `E-ALGORITHM` |
| 8 | SHA-256 de `datos.enc` = `encryptedSha256`; en `multipart`, también cada parte | `422` `E-HASH` |
| 9 | `publicParametersSha256` correcto (8.5) | `422` `E-PARAMS-HASH` |
| 10 | `certificado.pem` es X.509 válido, RSA-2048, CN = `sourceNode`, vigente | `422` `E-CERT` |
| 11 | Huella del certificado = `certificateThumbprintSha256` | `422` `E-CERT-THUMBPRINT` |
| 12 | Firma válida sobre la cadena 8.4 | `422` `E-SIGNATURE` |
| 13 | `timestampUtc` dentro de ±10 min del reloj del receptor | `422` `E-TIMESTAMP` |
| 14 | `packetId` no visto antes | `409` `E-DUPLICATE` |

- Si el `sourceNode` no está fijado en el directorio, el paquete **PUEDE** aceptarse en la bandeja, pero **DEBE** mostrarse como “Remitente no confirmado”.
- Si está fijado y la huella no coincide → `403` `E-CERT-UNTRUSTED`.

### 13.2 Al recibir una petición `/api/crypto/*`

1. Validaciones de tamaño (y de 13.1 sobre `package` en `inverse`).
2. `requesterCertificate` válido; CN = `requesterNode`; huella fijada o confirmable.
3. `requestSignature` válida sobre los bytes exactos de `request`.
4. `targetNode` = propio `nodeId`.
5. `timestampUtc` dentro de ±10 min; `requestId` no repetido.
6. El algoritmo es propio → si no, `404` `E-ALGORITHM-NOT-PROVIDED`.
7. Sobre `secrets` dirigido a este nodo y descifrable → si no, `401` `E-ENV-RECIPIENT` / `E-ENV-DECRYPT`.
8. Secretos y opciones válidos según el perfil → si no, `400` `E-PARAMS`.

### 13.3 Reglas generales

- Comparaciones de hash, MAC y firmas **DEBEN** hacerse en tiempo constante.
- Los secretos **NO DEBEN** aparecer en bitácoras, URLs, encabezados ni en `manifest.json`.
- Los archivos recibidos **NO DEBEN** ejecutarse ni abrirse automáticamente.
- El nodo **DEBERÍA** limitar a 10 peticiones `/api/crypto/*` simultáneas y responder `503` `E-BUSY` si se supera.

---

## 14. Errores

Formato `application/problem+json` (RFC 9457):

```json
{
  "type": "https://centrociber.local/errors/E-HASH",
  "title": "Integridad inválida",
  "status": 422,
  "code": "E-HASH",
  "detail": "El SHA-256 de datos.enc no coincide con encryptedSha256.",
  "nodeId": "EQ05",
  "requestId": "0b8d6c1e-...",
  "timestampUtc": "2026-11-25T15:47:04Z"
}
```

- `code` **DEBE** ser uno del Anexo B. `detail` es libre y en español.
- `type` es un identificador, no necesita resolverse.

---

## 15. Bandeja de Solicitudes y Consultas

```text
[Emisor] ──POST .zip──► [Validaciones 13.1] ──OK──► [Solicitudes: Pendiente]
                                                      │
                                    ┌─────────────────┴─────────────────┐
                                    ▼                                   ▼
                               [Aceptar]                           [Rechazar]
                                    │                                   │
                       Inserta en [Consultas]                 Estado "Rechazada"
                       con origen "Recibido"                  (zip PUEDE descartarse)
```

- **Solicitudes** **DEBE** mostrar: `sourceNode`, IP de origen, nombre del zip, `algorithmCode`, `operationName`, resultado de validación (`Firma OK` / `Inválida` / `Remitente no confirmado`) y botones **Aceptar** / **Rechazar**.
- **Consultas** **DEBE** permitir: descargar el zip, ejecutar `inverse` (local o delegado), reenviar a otro nodo (9.6) y ver el manifiesto.
- Orígenes en Consultas: `Generado` (creado por el propio nodo o recibido de un `forward` delegado), `Recibido` (aceptado de la bandeja), `Resultado` (devuelto por un `inverse`).
- Estados de Solicitudes: `Pendiente`, `Aceptada`, `Rechazada`.
- El nodo **PUEDE** notificar al emisor la decisión; no es obligatorio en v2.0.

---

## 16. Pruebas de interoperabilidad y conformidad

### 16.1 Vectores de prueba (cada equipo **DEBE** publicarlos)

En el repositorio compartido (sección 17), carpeta `vectores/EQNN/`:

| Archivo | Contenido |
| :--- | :--- |
| `certificado.pem` | Certificado de prueba del nodo |
| `privada-PRUEBA.pem` | Llave privada **solo de prueba** (nunca la real) |
| `cadena-firma.txt` | Cadena 8.4 de un paquete de ejemplo |
| `params-canonicos.txt` | Texto canónico 8.5 y su hash esperado |
| `<ALGORITMO>_ejemplo.zip` | Un paquete `package` por algoritmo asignado |
| `<ALGORITMO>_secretos.json` | Secretos en claro usados en el ejemplo |
| `<ALGORITMO>_original.*` | Archivo original esperado tras `inverse` |

### 16.2 Lista de conformidad mínima

- [ ] Responde `GET /api/status`, `/api/certificate` y `/api/algorithms` en `5000 + n`.
- [ ] Emite el anuncio UDP cada 30 s y detecta los anuncios de otros.
- [ ] Escaneo HTTP de respaldo y alta manual funcionan.
- [ ] Genera certificado RSA-2048 autofirmado con CN = `nodeId`.
- [ ] Valida correctamente los 16.1 de los demás equipos (firma, hash, parámetros canónicos).
- [ ] Rechaza: zip con 4 archivos, hash alterado, firma alterada, timestamp viejo, `packetId` repetido (con el código correcto).
- [ ] `forward` e `inverse` remotos funcionan para cada algoritmo propio.
- [ ] Puede delegar al menos un algoritmo de cada otro equipo.
- [ ] Sobre `CC-ENV-1` interoperable en ambos sentidos.

### 16.3 Matriz de interoperabilidad

Cada equipo registra qué combinaciones probó (solicitante × algoritmo) con fecha y resultado. Se integra en el reporte general.

---

## 17. Gobierno del estándar

| Tema | Acuerdo |
| :--- | :--- |
| Coordinador del estándar | **Por definir** (sección 18) |
| Repositorio compartido | **Por definir**: un solo repositorio con este documento, la tabla 4.1 y la carpeta `vectores/` |
| Cambios | Cualquier equipo propone un cambio por escrito; se aprueba por mayoría de equipos con nodo activo |
| Versionado | `MAYOR.MENOR`: un cambio que rompe compatibilidad sube la mayor; campos o algoritmos nuevos opcionales suben la menor |
| Congelamiento | **Por definir**: fecha a partir de la cual no se aceptan cambios a v2.x |
| Perfiles de algoritmo | Cada dueño confirma los nombres de parámetros de la tabla 4.2 antes del congelamiento |
| Prueba integrada | **Por definir**: sesión con todos los nodos en la misma red para llenar la matriz 16.3 |

---

## 18. Pendientes por confirmar

- [ ] **Equipo 4:** confirmar que le corresponden `DIFFIEHELLMAN` (7) y `CAESAR` (8).
- [ ] **Algoritmos 17–21:** confirmar si quedarán sin dueño o si se asignarán a equipos adicionales.
- [ ] **Cada equipo dueño:** confirmar parámetros secretos y públicos de la tabla 4.2.
- [ ] **Red para pruebas:** confirmar si la red escolar permite broadcast UDP y tráfico entre clientes; si no, definir router o hotspot dedicado.
- [ ] **Coordinador, repositorio y fecha de congelamiento** (sección 17).
- [ ] **Equipos con HTTPS:** cada equipo declara si lo ofrecerá.

---

## Anexo A. Ejemplos completos

### A.1 `manifest.json` tipo `package` (HASHSHA, Equipo 8)

```json
{
  "version": "2.0",
  "packetType": "package",
  "packetId": "550e8400-e29b-41d4-a716-446655440000",
  "requestId": null,
  "sourceNode": "EQ08",
  "sourceTeam": 8,
  "sourceIp": "192.168.1.14:5008",
  "producerNode": "EQ08",
  "timestampUtc": "2026-11-25T15:47:00Z",
  "algorithmId": 15,
  "algorithmCode": "HASHSHA",
  "algorithmName": "SHA-256",
  "operation": "forward",
  "operationName": "calcular hash",
  "payloadMode": "file",
  "originalFileName": "documento.pdf",
  "originalExtension": ".pdf",
  "originalSizeBytes": 14820,
  "contentType": "application/pdf",
  "encryptedSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "encryptedSizeBytes": 14820,
  "parts": null,
  "keyRef": null,
  "publicParameters": {
    "hashAlgorithm": "SHA-256",
    "digestHex": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
  },
  "publicParametersSha256": "<sha256 del texto canónico>",
  "verification": null,
  "resultEnvelope": null,
  "certificateThumbprintSha256": "A1B2C3D4E5F6...",
  "signatureAlgorithm": "RSA-PSS-SHA256",
  "manifestSignatureBase64": "MEUCIQ..."
}
```

Nombre del zip: `EQ08_HASHSHA_20261125_154700_9F86D081.zip`

### A.2 `manifest.json` tipo `result` (inverse de AESGCM por EQ01 para EQ05)

```json
{
  "version": "2.0",
  "packetType": "result",
  "packetId": "a3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
  "requestId": "0b8d6c1e-2f3a-4b5c-8d9e-0a1b2c3d4e5f",
  "sourceNode": "EQ01",
  "sourceTeam": 1,
  "sourceIp": "192.168.1.21:5001",
  "producerNode": "EQ01",
  "timestampUtc": "2026-11-25T16:02:10Z",
  "algorithmId": 1,
  "algorithmCode": "AESGCM",
  "algorithmName": "AES-256-GCM",
  "operation": "inverse",
  "operationName": "descifrar",
  "payloadMode": "file",
  "originalFileName": "documento.pdf",
  "originalExtension": ".pdf",
  "originalSizeBytes": 14820,
  "contentType": "application/pdf",
  "encryptedSha256": "<sha256 de resultado.enc>",
  "encryptedSizeBytes": 14836,
  "parts": null,
  "keyRef": null,
  "publicParameters": {},
  "publicParametersSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "verification": null,
  "resultEnvelope": {
    "envelope": "CC-ENV-1",
    "recipientNode": "EQ05",
    "recipientThumbprintSha256": "D4E5...",
    "wrappedKeyBase64": "...",
    "nonceBase64": "...",
    "tagBase64": "..."
  },
  "certificateThumbprintSha256": "C3D4...",
  "signatureAlgorithm": "RSA-PSS-SHA256",
  "manifestSignatureBase64": "..."
}
```

Nombre del zip: `RES_EQ01_AESGCM_20261125_160210_<SHA8>.zip`

### A.3 Petición `inverse` para HMACSHA256 (EQ03 pide a EQ08)

```json
{
  "version": "2.0",
  "requestId": "6e7f8a9b-0c1d-4e2f-9a3b-4c5d6e7f8a9b",
  "requesterNode": "EQ03",
  "targetNode": "EQ08",
  "timestampUtc": "2026-11-25T16:10:00Z",
  "algorithmCode": "HMACSHA256",
  "operation": "inverse",
  "payloadMode": "file",
  "originalFileName": "contrato.pdf",
  "options": {},
  "keyId": null,
  "secrets": {
    "envelope": "CC-ENV-1",
    "recipientNode": "EQ08",
    "recipientThumbprintSha256": "A1B2C3D4E5F6...",
    "wrappedKeyBase64": "...",
    "nonceBase64": "...",
    "tagBase64": "...",
    "ciphertextBase64": "..."
  }
}
```

El resultado trae `verification: { "valid": true, "detail": "HMAC coincide" }` y el original cifrado para EQ03 en `resultado.enc`.

---

## Anexo B. Catálogo de códigos de error

| Código | HTTP | Significado |
| :--- | :---: | :--- |
| `E-SIZE` | 413 | Cuerpo o paquete mayor a 50 MB |
| `E-ZIP-INVALID` | 400 | No es un zip válido |
| `E-ZIP-STRUCTURE` | 400 | Archivos faltantes, sobrantes, carpetas o rutas inválidas |
| `E-ZIP-BOMB` | 400 | Tamaño descomprimido o razón de compresión excesivos |
| `E-MANIFEST` | 400 | Manifiesto inválido o con campos faltantes |
| `E-VERSION` | 400 | Versión de protocolo no soportada |
| `E-ALGORITHM` | 400 | `algorithmId` / `algorithmCode` inexistentes o inconsistentes |
| `E-PARAMS` | 400 | Opciones o secretos inválidos para el algoritmo |
| `E-REQUEST` | 400 | Petición `/api/crypto/*` mal formada o partes faltantes |
| `E-REQUEST-SIGNATURE` | 401 | Firma de la petición inválida |
| `E-ENV-RECIPIENT` | 401 | El sobre no está dirigido a este nodo |
| `E-ENV-DECRYPT` | 401 | El sobre no se pudo abrir |
| `E-CERT-UNTRUSTED` | 403 | Huella distinta a la fijada para ese nodo |
| `E-ALGORITHM-NOT-PROVIDED` | 404 | Este nodo no provee el algoritmo |
| `E-KEY-NOT-FOUND` | 404 | `keyId` desconocido |
| `E-KEY-FORBIDDEN` | 403 | El `keyId` no permite a este solicitante |
| `E-JOB-NOT-FOUND` | 404 | `jobId` desconocido o expirado |
| `E-DUPLICATE` | 409 | `packetId` o `requestId` repetido |
| `E-UNSUPPORTED-MEDIA` | 415 | Tipo de contenido no soportado |
| `E-HASH` | 422 | SHA-256 de contenido no coincide |
| `E-PARAMS-HASH` | 422 | `publicParametersSha256` no coincide |
| `E-CERT` | 422 | Certificado inválido, vencido o con CN incorrecto |
| `E-CERT-THUMBPRINT` | 422 | Huella del certificado no coincide con el manifiesto |
| `E-SIGNATURE` | 422 | Firma del manifiesto inválida |
| `E-TIMESTAMP` | 422 | `timestampUtc` fuera de la ventana de ±10 min |
| `E-VERIFY-FAILED` | 422 | `inverse` de hash/MAC/firma terminó con `valid: false` (solo si el nodo decide reportarlo como error; por defecto va en `verification`) |
| `E-INTERNAL` | 500 | Error interno del proveedor |
| `E-BUSY` | 503 | Nodo ocupado o no acepta paquetes |
| `E-TIMEOUT` | 504 | El proveedor no pudo completar ni crear un trabajo asíncrono |

---

## Anexo C. Valores de referencia rápida

| Concepto | Valor |
| :--- | :--- |
| Versión de protocolo | `2.0` |
| `nodeId` | `EQ` + 2 dígitos |
| Puerto HTTP | `5000 + teamNumber` |
| Puerto HTTPS (opcional) | `5100 + teamNumber` |
| Puerto UDP de anuncio | `5099` |
| Intervalo de anuncio | 30 s |
| Nodo fuera de línea tras | 90 s sin señal |
| Escaneo de respaldo | Subred /24, puertos 5001–5020, 500 ms por intento |
| Llave de identidad | RSA-2048, certificado autofirmado 365 días |
| Firma | RSA-PSS, SHA-256, MGF1-SHA256, sal 32 bytes |
| Sobre | `CC-ENV-1` = RSA-OAEP-SHA256 + AES-256-GCM |
| Huella de certificado | SHA-256 del DER, hex MAYÚSCULAS |
| Hash de contenido | SHA-256 hex minúsculas |
| Tamaño máximo de paquete | 50 MB |
| Tamaño máximo descomprimido | 200 MB |
| Ventana de tiempo | ±10 min |
| Tope síncrono | 30 s, luego `202` + `jobId` |
| Retención de resultados asíncronos | ≥ 1 h |
| Retención de llaves `keyId` | Hasta el cierre del semestre |
