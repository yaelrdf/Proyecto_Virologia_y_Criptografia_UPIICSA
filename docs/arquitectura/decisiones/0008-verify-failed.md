# ADR 0008 — `valid: false` se devuelve con 200

- **Estado:** Aceptada (Anexo B y plan §2.1)
- **Fecha:** 2026-11-26

## Contexto

El Anexo B dice que `E-VERIFY-FAILED` se usa «solo si el nodo decide reportarlo como error; por defecto va en `verification`».

## Decisión

EQ08 responde **200** con un `result` cuyo `verification` es `{ "valid": false, "detail": "Hash no coincide" | "HMAC no coincide" }`. Nunca devuelve `E-VERIFY-FAILED`.

## Consecuencias

- El solicitante recibe siempre el original y el veredicto.
- Las interfaces deben mostrar el veredicto con claridad (EQ08 lo muestra en rojo).
