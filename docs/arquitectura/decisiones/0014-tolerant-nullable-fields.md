# ADR 0014 — Campos anulables ausentes en manifiestos de otros nodos

- **Estado:** Propuesta (interpretación de §9.5; avisar a EQ01 y al coordinador)
- **Fecha:** 2026-11-27

## Contexto

En la prueba con EQ01, sus paquetes llegaron a EQ08 sin los campos `requestId` ni `parts`, y EQ08 los rechazó con `400 E-MANIFEST: Faltan campos obligatorios: requestId, parts`. Lo mismo pasaba en `POST /api/crypto/inverse`.

La tabla §9.5 marca esos campos como obligatorios con tipo «UUID | null» o «arreglo | null». La lectura estricta es que deben estar presentes aunque valgan `null`. Sin embargo, varios serializadores (Newtonsoft con `NullValueHandling.Ignore`, Jackson con `NON_NULL`, `JSON.stringify` con `undefined`) **omiten** los nulos por defecto. Ninguno de estos campos entra en la cadena de firma §8.4, así que omitirlos no afecta la integridad ni la autenticidad del paquete.

## Decisión

- **EQ08 es estricto al enviar**: sus manifiestos siempre incluyen todos los campos de §9.5, también los nulos.
- **EQ08 es tolerante al recibir**: si faltan `requestId`, `parts` o `keyRef`, o en un `result` faltan `verification` o `resultEnvelope`, se tratan como `null`.
- Siguen siendo obligatorios con valor los demás campos de §9.5, incluidos todos los que entran en la firma. Si alguno falta → `E-MANIFEST`.
- `parts` sigue siendo obligatorio cuando `payloadMode = multipart`, y `resultEnvelope` cuando se quiere abrir un resultado.
- Todo rechazo de la API queda registrado en la bitácora (`api.rejected`), con IP, nodo, código y detalle, y se muestra en la Bandeja para depurar con el otro equipo.

## Consecuencias

- EQ08 interopera con los nodos que omiten los nulos, sin bajar la seguridad: la firma, los hashes y el certificado se siguen validando.
- Se debe avisar a EQ01 que, para cumplir §9.5 al pie de la letra, envíe los campos con `null`, y proponer al coordinador aclararlo en la v2.1: «los campos anulables PUEDEN omitirse».
