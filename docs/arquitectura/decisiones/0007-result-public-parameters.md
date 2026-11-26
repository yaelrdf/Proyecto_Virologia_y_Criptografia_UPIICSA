# ADR 0007 — `publicParameters` de un paquete `result`

- **Estado:** Propuesta
- **Fecha:** 2026-11-26

## Contexto

La tabla 9.5 no dice qué `publicParameters` lleva un `result`. El Anexo A.2 muestra `{}`.

## Decisión

Los `result` de EQ08 llevan `publicParameters = {}` (hash canónico = SHA-256 de la cadena vacía). El veredicto va en `verification` y la variante usada se refleja en `algorithmName` (p. ej. `SHA-512`). `keyRef` se copia del paquete original.

## Consecuencias

- Coincide con el ejemplo normativo A.2.
- El solicitante obtiene el resultado completo abriendo `resultEnvelope`.
