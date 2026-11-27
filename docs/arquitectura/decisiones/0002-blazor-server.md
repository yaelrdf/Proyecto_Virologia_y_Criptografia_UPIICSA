# ADR 0002 — Blazor Web App con interactividad Server

- **Estado:** Aceptada (plan §3)
- **Fecha:** 2026-11-26

## Contexto

La interfaz debe estar en español, sin inicio de sesión, accesible solo desde la LAN y con notificaciones en tiempo real (nuevas solicitudes, trabajos terminados).

## Decisión

Usar **Blazor Web App** con renderizado interactivo **Server** hospedado en el mismo proceso que la API. Los servicios publican eventos en `NotificationHub` y los componentes se suscriben; el circuito SignalR de Blazor lleva la actualización al navegador.

## Consecuencias

- Un solo proceso y un solo puerto para la interfaz y la API; no hay que escribir JavaScript ni un cliente aparte.
- Los componentes llaman a los servicios directamente, sin HTTP interno.
- Requiere conexión WebSocket abierta: el filtro solo-LAN (`LanOnlyMiddleware`) limita la interfaz a IP privadas y loopback, mientras `/api` queda abierta a toda la LAN (§5.1).
