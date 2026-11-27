# ADR 0010 — Ubicación de constantes y contratos

- **Estado:** Aceptada
- **Fecha:** 2026-11-26

## Contexto

`CLAUDE.md` fija las dependencias `Web → Application → (Crypto, Packaging, Discovery, Infrastructure)`, `Packaging → Crypto`, y `Crypto` sin dependencias. `Discovery` e `Infrastructure` necesitan las constantes del protocolo (puertos, códigos).

## Decisión

- `ProtocolConstants`, `ErrorCodes`, `Identifiers` y `AlgorithmCatalog` viven en `CentroCiber.Crypto.Protocol` (hoja del grafo).
- `Discovery` e `Infrastructure` dependen **solo** de `Crypto` (hoja), nunca entre sí ni de `Application`.
- Los contratos JSON de la API (`StatusResponse`, `CryptoRequest`, ...) y el constructor de peticiones firmadas viven en `CentroCiber.Packaging`, para que `MockNode` y las pruebas los reutilicen sin depender de la Web.

## Consecuencias

- No hay ciclos; cada proyecto se prueba por separado.
- Una sola fuente para los literales del protocolo.
