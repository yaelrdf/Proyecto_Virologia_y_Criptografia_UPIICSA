# ADR 0013 — Variantes y parámetros estrictos de HASHSHA y HMACSHA256

- **Estado:** Aceptada (plan §1)
- **Fecha:** 2026-11-26

## Contexto

§4.1 lista SHA-3 y HMAC-SHA512 como posibles variantes; el plan del equipo decidió ofrecer solo SHA-256, SHA-512 y HMAC-SHA256. §13.2 #8 pide rechazar con `E-PARAMS` opciones y secretos inválidos «según el perfil».

## Decisión

- Se anuncian y aceptan solo `SHA-256`, `SHA-512` y `HMAC-SHA256`; `SHA3-256` y `HMAC-SHA512` → `E-PARAMS`.
- Opciones o secretos no declarados en el perfil → `E-PARAMS` (`HASHSHA` no acepta secretos).
- La clave HMAC debe ser Base64 de ≥ 32 bytes. Las variantes se pueden deshabilitar en Ajustes; una variante deshabilitada → `E-PARAMS`.

## Consecuencias

- Errores claros en lugar de resultados inesperados.
- Si otro equipo envía opciones extra, recibirá `E-PARAMS` con el nombre del parámetro.
