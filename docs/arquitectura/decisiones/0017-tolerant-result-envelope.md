# ADR 0017 — Apertura tolerante de resultados (`resultEnvelope`)

- **Estado:** Propuesta (compatibilidad con EQ01, documentada por RelayCryptoNode/EQ06)
- **Fecha:** 2026-11-27

## Contexto

§8.3 indica que, en un `result`, el texto cifrado va en `resultado.enc` y el sobre (sin `ciphertextBase64`) en `resultEnvelope`, con AAD = `packetId` del resultado.

RelayCryptoNode (EQ06) agrega tolerancias porque EQ01 en la práctica:
1. mete el **sobre CC-ENV-1 completo** (con `ciphertextBase64`) **dentro de `resultado.enc`**, sin `resultEnvelope` en el manifiesto;
2. puede mandar la **etiqueta GCM pegada al final** del texto cifrado, sin `tagBase64` (es lo normal en Java, Python y WebCrypto);
3. usa como AAD otro identificador: el `requestId` de la petición o el `packetId` del paquete de origen.

Esto se sabe por la lectura de su código como referencia; no se copió nada, porque su licencia es propietaria. Con la implementación estricta, EQ08 no podía abrir esos resultados: `E-MANIFEST` o `E-ENV-DECRYPT`.

## Decisión

`ResultEnvelopeOpener` (`src/CentroCiber.Crypto/Envelope/ResultEnvelopeOpener.cs`) abre los resultados así:

1. Si `resultado.enc` es un JSON con `wrappedKeyBase64` y `ciphertextBase64`, usa ese sobre; si no, usa `resultEnvelope` con `resultado.enc` como texto cifrado.
2. Si falta `tagBase64`, toma los últimos 16 bytes del texto cifrado como etiqueta.
3. Prueba los AAD en este orden: `packetId` del resultado (estándar), `requestId` de la petición, `requestId` del manifiesto y `packetId` del paquete de origen.

**No se relaja nada criptográfico.** Se siguen exigiendo RSA-OAEP-SHA256, AES-256-GCM con nonce de 12 bytes y etiqueta de 16, y el destinatario correcto (`recipientNode` / `recipientThumbprintSha256` cuando vienen). No se acepta OAEP-SHA1 ni nombres de campos fuera del estándar.

EQ08 sigue **enviando** sus resultados según §8.3. El `MockNode` puede imitar las variantes (`--omit-nulls --envelope-in-data --append-tag`) para pruebas.

## Consecuencias

- EQ08 abre los resultados de EQ01 y de cualquier nodo que siga §8.3.
- Probar varios AAD no debilita GCM: cada intento sigue autenticando el texto cifrado con la clave del sobre, que solo EQ08 puede abrir.
- Se propone al coordinador fijar en la v2.1 el AAD y la ubicación del sobre.
