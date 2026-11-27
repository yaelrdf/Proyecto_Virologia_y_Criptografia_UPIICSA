# ADR 0012 — `NotBefore` del certificado adelantado 10 minutos

- **Estado:** Aceptada
- **Fecha:** 2026-11-26

## Contexto

§7 pide vigencia de «365 días desde su generación». Si otro nodo tiene el reloj atrasado unos minutos, vería el certificado de EQ08 como «aún no vigente» (`E-CERT`).

## Decisión

`NotBefore = ahora − 10 min` (la misma ventana de §13) y `NotAfter = ahora + 365 días`. La serie es aleatoria de 72 bits (≥ 64 bits, positiva). Se agregan las extensiones *Basic Constraints* (no CA), *Subject Key Identifier* y SAN (`eq08`, `localhost`), además de *Key Usage* crítico con `digitalSignature` y `keyEncipherment`.

## Consecuencias

- Tolerancia a relojes desfasados sin cambiar la vigencia efectiva de 365 días.
