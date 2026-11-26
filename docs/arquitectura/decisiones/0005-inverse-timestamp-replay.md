# ADR 0005 — En `inverse`, las reglas #13 y #14 se aplican a la petición

- **Estado:** Propuesta (interpretación del estándar; requiere aprobación de los equipos)
- **Fecha:** 2026-11-26

## Contexto

El §13.1 dice que las 14 validaciones aplican «al recibir un paquete (bandeja o `inverse`)». Si se aplicaran literalmente la ventana de ±10 min (#13) y el rechazo de `packetId` repetido (#14) al paquete embebido en `POST /api/crypto/inverse`, sería imposible invertir un paquete guardado en Consultas más de 10 minutos después de crearlo (flujo §11.4, donde el usuario abre el paquete «después»), o verificar dos veces el mismo paquete.

## Decisión

En `inverse`, EQ08 aplica al paquete las validaciones #1–#12 (y la de huella fijada) y aplica la ventana de tiempo y la anti-repetición a la **petición** (`timestampUtc` y `requestId`, §13.2 #5), que es la que realmente viaja en ese momento. En la bandeja (`/api/requests/receive`) se aplican las 14 sobre el paquete.

## Consecuencias

- Un mismo paquete puede invertirse varias veces con peticiones distintas.
- La protección contra repetición se mantiene: cada petición lleva un `requestId` nuevo, firmado y con marca de tiempo.
- Se registra en `docs/backlog/Backlog.md` (Pendientes) y se propondrá al coordinador para la versión 2.1.
