# Compatibilidad con RelayCryptoNode (EQ06)

| Campo | Valor |
| --- | --- |
| Referencia | [Vidruck/RelayCryptoNode](https://github.com/Vidruck/RelayCryptoNode), rama `main`, commit `522433a` («LSBSTEGO compatible con el EQ01 (cabecera LSBC)») |
| Nodo | `EQ06`, puerto HTTP 5006 (y 5000 para su formato v1), UDP 5099 |
| Algoritmos propios | 11 `LSBSTEGO` y 12 `EUCLIDESAFFINE`. En su «modo v3» ejecuta los 21 localmente |
| Versión de EQ08 compatible | **1.1.0** (rama `release/v1.1-relay-compat`) |
| Fecha de revisión | 2026-11-27 |

> **Licencia.** RelayCryptoNode tiene licencia **propietaria** («todos los derechos reservados»). Se leyó solo como referencia, en un clon temporal fuera de este repositorio. **No se copió, adaptó ni ejecutó su código**: todo lo de este documento describe comportamiento observable y la implementación de EQ08 es propia (GPL-3.0).

## 1. Comparación

| Tema | Estándar v2.0 | EQ08 1.0 | RelayCryptoNode (EQ06) | ¿Rompe la interoperabilidad? | Acción en EQ08 1.1 |
| --- | --- | --- | --- | --- | --- |
| Endpoints `/api/*` | §10.2 | Todos | Todos (`jobs` y `keys` como stubs) | No | — |
| `GET /api/status` | §10.3 | Campos del estándar | Agrega `supportedProtocolVersions`, `certificateThumbprint`, `role` y `endpoint` | No (se ignoran) | EQ08 publica `supportedProtocolVersions: ["2.0"]` y `nodeVersion` |
| `GET /api/algorithms` | §10.4 | Perfil estándar | Agrega `notes`; secretos con `type: "text"` y `optional` | No | La interfaz muestra `notes` |
| `LSBSTEGO` `forward` | Parte `cover` (§10.6) | La página Operar sí la enviaba; Enviar no | Exige `cover` (PNG/BMP) | **Sí**, desde la página Enviar | Campo «Imagen portadora» en Enviar cuando el perfil pide `cover` |
| Partes multipart | §10.6 | `request` como archivo JSON; firma y certificado como texto o archivo | `request` sin nombre de archivo (campo); firma y certificado como texto | No: ambos leen archivo o campo | — |
| Encabezados `X-CC-*` | §10.1 | Sí | Sí | No | — |
| Respuesta de `forward` | `package` | `package` | `package` (su README dice `RES_*`, pero el código arma `package`) | No | — |
| Manifiesto: campos anulables omitidos | §9.5 | Rechazaba (`E-MANIFEST`) antes del ADR 0014 | Tolera; por omisión exige `requestId` (su «candado») | Sí con nodos tipo EQ01 | ADR 0014 (ya en 1.1) |
| Manifiesto: campos informativos omitidos | §9.5 | Rechazaba | Exige solo los firmados y completa el resto | Sí con nodos tipo EQ01 | **ADR 0016**: exige solo los firmados, completa el resto y lo informa en la Bandeja |
| Resultado con el sobre dentro de `resultado.enc` | §8.3: sobre en `resultEnvelope` | No lo abría | Lo abre (observado en EQ01) | **Sí** | **ADR 0017** |
| Etiqueta GCM pegada al cifrado | §8.3: `tagBase64` | No | La acepta | Sí | ADR 0017 |
| AAD del resultado | `packetId` del resultado | Solo ese | Prueba también `requestId`, `packetId` de origen y AAD declarado | Sí | ADR 0017: `packetId`, `requestId` y `packetId` de origen. No se aceptan AAD vacío, nombres de campo ajenos ni OAEP-SHA1 |
| Reenvío de AESGCM/CHACHA20 | §9.6: nuevo `packetId` | Conserva el `packetId` (ADR 0015) | Genera uno nuevo; su proveedor usa como AAD el `packetId` del paquete que recibe | Compatible: si EQ06 recibe nuestros reenvíos, el `packetId` es el original | — |
| `inverse` delegado | §13.1 | Ventana y anti-repetición sobre la petición (ADR 0005) | Reempaqueta con fecha nueva antes de pedir `inverse` (asume la lectura estricta) | No: EQ08 acepta ambos | — |
| Beacon UDP | §6.1 | Estándar | Estándar | No | — |
| Escaneo | §6.2: /24, puertos 5001–5020, a mano o cada ≥ 5 min | Igual | Hasta una /22, puertos 5000–5020, cada 30 s | No (EQ06 nos encuentra en 5008) | No se adopta: contradice §6.2 |
| Formato v1 (puerto 5000, `/api/v1/*`) | Fuera de v2.0 | No | Lo soporta, con un modo de clave fija `clave-aes-256-segura` | No para v2.0 | **No se adopta**: v1 está fuera del alcance (CLAUDE.md) y su modo de clave fija es inseguro |
| Interfaz protegida con login | — | Solo LAN, sin login | Login para el panel | No | — |

## 2. Cambios en EQ08 1.1.0 por esta revisión

1. **ADR 0016**: solo los campos de la cadena de firma son obligatorios al recibir; los informativos omitidos se completan y se muestran en la Bandeja como «Campos omitidos».
2. **ADR 0017**: los resultados se abren aunque traigan el sobre dentro de `resultado.enc`, la etiqueta pegada o un AAD alternativo.
3. `/api/status` publica `supportedProtocolVersions` y `nodeVersion`; la interfaz muestra las `notes` de los perfiles ajenos.
4. La página **Enviar** pide la imagen portadora cuando el perfil del dueño la exige (`LSBSTEGO`). La **Bandeja** previsualiza `datos.enc` cuando es una imagen (la imagen con el mensaje oculto).
5. El **MockNode** imita las variantes observadas (`--omit-nulls --envelope-in-data --append-tag`), y hay pruebas automáticas para cada una (`DelegationTests.Delegation_tolerates_owner_variants`, `ResultEnvelopeOpenerTests`).

## 3. Cómo probar EQ08 ↔ EQ06 en la LAN

1. Arranca ambos nodos en la misma red, con el firewall abierto: EQ08 en 5008/5108, EQ06 en 5006 y UDP 5099 en los dos.
2. En EQ08, en **Nodos**, EQ06 debe aparecer por el anuncio UDP; si no, usa alta manual con `IP:5006`. Compara su huella con la que ve el equipo 6 y pulsa **Confirmar huella**. EQ06 hace lo mismo en su sección «Red» con EQ08.
3. **EQ08 → EQ06 (delegar)**:
   - En **Operar (ida)** o **Enviar**, elige `EUCLIDESAFFINE` (con secretos `a` y `b`) o `LSBSTEGO` (con imagen portadora PNG o BMP; contraseña opcional).
   - Luego haz `inverse` desde Consultas o desde la Bandeja del destinatario.
4. **EQ06 → EQ08**: el equipo 6 pide `HASHSHA` o `HMACSHA256` a EQ08 (`/api/crypto/forward` e `inverse`). Revisa **Ajustes → Bitácora** y **Bandeja → Rechazos recientes**.
5. **Bandejas**:
   - EQ08 envía un paquete a EQ06 desde **Enviar** y EQ06 lo ve como «Firma OK».
   - EQ06 envía a EQ08 y el paquete aparece en la **Bandeja**. Si el manifiesto omitía campos, se ven en «Campos omitidos».
6. Anota cada combinación en la [matriz](Matriz.md).

## 4. Pendiente

- 🖐 Prueba real EQ08 ↔ EQ06 en la LAN; aquí solo se probó contra el MockNode con las variantes.
- Avisar a EQ06 de la contradicción §4.2/§9.6 (ADR 0015): al reenviar AESGCM a un tercero, su `Rewrap` cambia el `packetId` y el dueño ya no puede descifrar.
- Avisar a EQ06 que su modo v1 con clave fija (`clave-aes-256-segura`) no debería usarse fuera de pruebas.
