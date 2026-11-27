# ADR 0011 — Acceso al resultado de un trabajo y destino incorrecto

- **Estado:** Propuesta
- **Fecha:** 2026-11-26

## Contexto

§10.7 dice que solo el `requesterNode` original puede descargar el resultado (encabezado `X-CC-Node`), pero no define el código de error. §13.2 #4 (`targetNode` ≠ propio) tampoco tiene código.

## Decisión

- Si `X-CC-Node` no coincide con el solicitante, o el trabajo no ha terminado, `GET /api/jobs/{id}/result` responde `404 E-JOB-NOT-FOUND` (no revela que el trabajo existe).
- `targetNode` distinto del propio → `400 E-REQUEST`.
- Un `algorithmCode` que no está en la tabla 4.1 → `400 E-ALGORITHM`; uno de la tabla que EQ08 no provee → `404 E-ALGORITHM-NOT-PROVIDED`.

## Consecuencias

- Códigos coherentes con el Anexo B; se proponen para la v2.1.
