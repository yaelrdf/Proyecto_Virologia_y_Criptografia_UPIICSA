# ADR 0015 — Al reenviar AESGCM y CHACHA20 se conserva el `packetId`

- **Estado:** Propuesta (contradicción entre §4.2 y §9.6; proponer al coordinador para la v2.1)
- **Fecha:** 2026-11-27

## Contexto

- §4.2: en `AESGCM` y `CHACHA20`, el AAD del cifrado es el **`packetId`** en UTF-8.
- §9.6: quien reenvía un paquete **DEBE** generar un `packetId` nuevo.

En el panel de pruebas, EQ08 delegó un cifrado AESGCM a EQ01 y reenvió el paquete a la bandeja de EQ09. Cuando EQ09 pidió a EQ01 descifrarlo, EQ01 usó como AAD el `packetId` nuevo y respondió `E-PARAMS: No se pudo descifrar`. Con un `packetId` nuevo, el AAD original se pierde y el paquete queda indescifrable para siempre. El flujo §11.3 (delegar y luego enviar a un tercero) queda roto para esos dos algoritmos.

## Decisión

Al reenviar un paquete de un algoritmo cuyo AAD es el `packetId` (`AlgorithmCatalog.PacketIdAadAlgorithms` = `AESGCM`, `CHACHA20`), EQ08 **conserva el `packetId`**. Todo lo demás de §9.6 se cumple: nuevo `timestampUtc`, `sourceNode` = EQ08, certificado de EQ08 y nueva firma. El resto de los algoritmos siguen recibiendo un `packetId` nuevo.

El `MockNode` (solo para pruebas locales) es tolerante: usa como AAD el `packetId` del paquete y, si no funciona y existe, el parámetro público no estándar `aadPacketId`. Su mensaje de error explica la causa.

## Consecuencias

- El dueño puede descifrar los paquetes reenviados por terceros.
- El receptor no ve el `packetId` repetido salvo que se le reenvíe el mismo paquete dos veces. En ese caso responde `E-DUPLICATE`, lo cual es razonable.
- Es una desviación de §9.6 #2 que se debe aprobar en el equipo y proponer al coordinador. Alternativa para la v2.1: que el AAD sea el `packetId` **del productor** y viaje en `publicParameters` (por ejemplo, `aadPacketId`).
