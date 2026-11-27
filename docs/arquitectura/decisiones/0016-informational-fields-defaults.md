# ADR 0016 — Solo los campos firmados son obligatorios al recibir

- **Estado:** Propuesta (amplía el ADR 0014; compatibilidad con RelayCryptoNode/EQ06 y EQ01)
- **Fecha:** 2026-11-27

## Contexto

El ADR 0014 toleró los campos anulables omitidos (`requestId`, `parts`, …). Al revisar RelayCryptoNode (EQ06), solo como referencia y sin copiar código por su licencia propietaria, se ve que esa implementación exige únicamente los campos de la cadena de firma §8.4 y la firma, y completa los informativos que otros equipos omiten (`sourceTeam`, nombres, tamaños…). La razón es que EQ01 omite también esos campos. Mientras EQ08 rechace con `E-MANIFEST` lo que EQ06 acepta, la red se fragmenta.

## Decisión

- **Obligatorios** (sin ellos no se puede verificar): `version`, `packetType`, `packetId`, `sourceNode`, `producerNode`, `algorithmCode`, `operation`, `timestampUtc`, `encryptedSha256`, `publicParametersSha256`, `certificateThumbprintSha256` y `manifestSignatureBase64`.
- **Informativos con valor deducible** (`PackageValidator.InformationalFields`):

  | Campo omitido | Valor que se usa |
  | --- | --- |
  | `sourceTeam` | Número que sale de `sourceNode` |
  | `algorithmId` | El de la tabla 4.1 |
  | `algorithmName` | El código |
  | `operationName` | El de la tabla 4.1 |
  | `payloadMode` | `file` |
  | `originalFileName` | `datos.bin` |
  | `originalExtension` | Extensión del nombre |
  | `originalSizeBytes` | 0 |
  | `contentType` | Por extensión |
  | `encryptedSizeBytes` | Tamaño real del contenido |
  | `publicParameters` | `{}`; su hash firmado se sigue comprobando, así que un `{}` falso falla con `E-PARAMS-HASH` |
  | `signatureAlgorithm` | `RSA-PSS-SHA256` |
  | `sourceIp` | «desconocida» |

- Los formatos de §3 se siguen validando sobre lo que venga, y las 14 validaciones de §13.1 no cambian.
- `ValidatedPackage.OmittedFields` informa qué omitió el remitente. La Bandeja lo muestra para avisarle al otro equipo.
- EQ08 sigue enviando **todos** los campos (§9.5).

## Consecuencias

- Ninguno de esos campos estaba protegido por la firma, así que la tolerancia no baja la seguridad.
- EQ08 acepta lo mismo que EQ06 y deja constancia de cada omisión.
