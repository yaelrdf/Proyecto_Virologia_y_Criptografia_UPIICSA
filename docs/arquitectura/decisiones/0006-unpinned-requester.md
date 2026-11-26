# ADR 0006 — Peticiones de un solicitante sin huella fijada

- **Estado:** Propuesta (interpretación de §13.2 #2)
- **Fecha:** 2026-11-26

## Contexto

§13.2 #2 pide «huella fijada **o confirmable**». Si EQ08 exigiera huella fijada, ningún nodo nuevo podría usar sus algoritmos hasta que el usuario de EQ08 lo confirmara a mano.

## Decisión

Si el `requesterNode` **no** está fijado, la petición se acepta (el certificado es válido, el CN coincide y la firma verifica) y el nodo se registra en el directorio como **pendiente de confirmar**, con origen `request`; la interfaz lo muestra para que el usuario lo confirme. Si **está** fijado y la huella difiere → `403 E-CERT-UNTRUSTED`.

## Consecuencias

- Interoperabilidad inmediata en la prueba integrada.
- Un atacante en la LAN podría usar los algoritmos de EQ08 (hash y HMAC). El riesgo es bajo: no hay llaves guardadas y el resultado va cifrado para quien pide.
