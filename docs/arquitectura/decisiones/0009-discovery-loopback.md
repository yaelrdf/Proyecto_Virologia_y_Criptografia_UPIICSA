# ADR 0009 — Descubrimiento configurable para pruebas en una sola máquina

- **Estado:** Aceptada
- **Fecha:** 2026-11-26

## Contexto

El §6.1 fija el puerto 5099 y los destinos de broadcast. En la nube y en una laptop se necesitan dos nodos en la misma máquina, y algunas redes bloquean el broadcast.

## Decisión

El puerto de escucha y los destinos del anuncio son configurables (`Node:Discovery:ListenPort`, `Node:Discovery:Targets`). Por omisión se usan los valores del estándar (5099, `255.255.255.255` y el broadcast de cada interfaz). El socket usa `ReuseAddress` y `EnableBroadcast` para que varias instancias compartan el puerto. Las pruebas usan destinos `127.0.0.1:<puerto>`.

## Consecuencias

- La red real sigue el estándar sin configuración extra.
- El escaneo HTTP (§6.2) y la alta manual siguen disponibles cuando el broadcast está bloqueado.
