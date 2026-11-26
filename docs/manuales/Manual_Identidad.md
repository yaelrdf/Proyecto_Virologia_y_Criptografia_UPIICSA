# Manual de identidad — Atalaya EQ08

> **Estado: propuesta para aprobación del equipo.** El nombre, el logotipo y la paleta pueden cambiar. Si se aprueban, se marca este documento como «Aprobado» con la fecha y quedan como identidad oficial del nodo.

## 1. Nombre

**Atalaya EQ08** — *nodo del Centro de Ciberseguridad Comunitario*.

- Una **atalaya** es una torre de vigilancia desde la que se observa el territorio y se avisa a los demás con señales. Así funciona el nodo: vigila la integridad (hash), autentica (HMAC), anuncia su presencia a la red (UDP) y se comunica con los otros nodos.
- Uso: «Atalaya EQ08» la primera vez y «Atalaya» después. En contextos técnicos del protocolo, el identificador sigue siendo `EQ08`.
- No se traduce ni se abrevia. No se escribe todo en mayúsculas (`ATALAYA`), salvo en el logotipo pequeño si hiciera falta.

## 2. Logotipo

Archivo maestro: [`docs/assets/logo.svg`](../assets/logo.svg). Es **original**, hecho con formas geométricas simples y sin marcas de terceros. También está en `src/CentroCiber.Web/wwwroot/img/logo.svg` y como favicon.

<p><img src="../assets/logo.svg" alt="Logotipo Atalaya EQ08" width="128" /></p>

Elementos:

- **Escudo hexagonal** azul: protección y la «celda» de una red de nodos.
- **Atalaya** blanca al centro: vigilancia.
- **Tres arcos de señal** turquesa: el anuncio a la red y la comunicación.
- **Dos nodos** laterales conectados: los demás equipos del Centro.

### Uso correcto

- Sobre fondo blanco, gris claro (`#F4F7FA`) o Azul Atalaya, con un margen libre igual a la altura de un arco de señal.
- Tamaño mínimo: 24 px en pantalla (favicon 16 px permitido) y 12 mm impreso.
- Junto al nombre: el logotipo a la izquierda y «Atalaya EQ08» en peso 700.

### Uso incorrecto

- ✘ Cambiar los colores, aplicar degradados o sombras.
- ✘ Deformar, rotar o recortar el escudo.
- ✘ Colocarlo sobre fotografías o fondos con poco contraste.
- ✘ Agregar logotipos de terceros (IPN, UPIICSA, marcas comerciales) dentro del escudo.

## 3. Paleta de colores

| Nombre | Hex | Uso |
| --- | --- | --- |
| Azul Atalaya | `#0B3D5C` | Marca, encabezado, barra de estado, títulos |
| Verde Señal | `#0F7B6C` | Botones de acción principal, enlaces |
| Turquesa Faro | `#5FD3C1` | Acentos sobre azul (navegación activa, arcos del logotipo, foco) |
| Rojo Alerta | `#B3261E` | Errores, huella cambiada, acciones destructivas |
| Ámbar (texto) | `#7A4D00` sobre `#FFF4DB` | Advertencias, «Remitente no confirmado» |
| Verde OK (texto) | `#0B6B3A` sobre `#E6F4EC` | «Firma OK», verificación válida |
| Texto | `#1B2430` | Texto principal |
| Texto secundario | `#4A5868` | Ayudas y subtítulos |
| Fondo | `#F4F7FA` | Fondo de página |
| Superficie | `#FFFFFF` | Tarjetas y tablas |
| Borde | `#D5DEE7` | Bordes y separadores |

Los colores están definidos como variables CSS en `src/CentroCiber.Web/wwwroot/app.css` (`--cc-azul`, `--cc-verde`, …).

### Contraste verificado (WCAG 2.1 AA)

Se calculó la razón de contraste con la fórmula de luminancia relativa de WCAG 2.1. AA exige ≥ 4.5:1 para texto normal.

| Combinación | Razón | AA texto normal |
| --- | --- | --- |
| `#1B2430` sobre `#FFFFFF` | 15.65:1 | ✅ |
| `#1B2430` sobre `#F4F7FA` | 14.56:1 | ✅ |
| `#4A5868` sobre `#FFFFFF` | 7.27:1 | ✅ |
| `#0B3D5C` sobre `#FFFFFF` (y al revés) | 11.44:1 | ✅ |
| `#FFFFFF` sobre `#0F7B6C` (botón) | 5.16:1 | ✅ |
| `#FFFFFF` sobre `#B3261E` (botón peligro) | 6.54:1 | ✅ |
| `#7A4D00` sobre `#FFF4DB` (advertencia) | 6.65:1 | ✅ |
| `#0B6B3A` sobre `#E6F4EC` (éxito) | 5.83:1 | ✅ |
| `#B3261E` sobre `#FDECEA` (error) | 5.72:1 | ✅ |
| `#5FD3C1` sobre `#0B3D5C` (navegación activa) | 6.30:1 | ✅ |
| `#E8EEF4` sobre `#0B3D5C` (texto en encabezado) | 9.78:1 | ✅ |

**No** usar Turquesa Faro como texto sobre blanco: su contraste es insuficiente. Solo va sobre Azul Atalaya.

## 4. Tipografía

Tipografías libres, con licencia SIL Open Font License:

| Uso | Tipografía | Respaldo del sistema |
| --- | --- | --- |
| Texto e interfaz | **Inter** (400, 600, 700) | Segoe UI, system-ui, Roboto, Arial |
| Código, huellas, hashes, nombres de zip | **IBM Plex Mono** (400) | Cascadia Mono, Consolas, Liberation Mono |

El nodo **no descarga fuentes de Internet**: debe funcionar en una LAN aislada. Si Inter o IBM Plex Mono están instaladas en la máquina se usan; si no, el navegador usa las de respaldo.

Jerarquía: título de página 24 px/700 en Azul Atalaya; subtítulo 18 px/700; texto 15 px/400; ayudas 13 px en texto secundario.

## 5. Iconografía y elementos

- Se usan **insignias de texto** en lugar de íconos para los estados (`Firma OK`, `Pendiente de confirmar`, `Huella cambiada`), porque son más claras y accesibles.
- Símbolos Unicode simples solo como apoyo: ✔ (paso válido), ✘ (paso fallido), ● (oyente UDP activo).
- Bordes redondeados de 10 px en tarjetas y de 6 px en botones y campos.
- Foco visible: contorno Turquesa Faro de 3 px en todos los controles.

## 6. Tono de voz

- **Español claro y directo**, en segunda persona («Confirma la huella», «Selecciona un paquete»).
- Los errores dicen **qué pasó y qué hacer**, con el código del estándar al inicio: «`E-TIMESTAMP`: timestampUtc está fuera de la ventana de ±10 minutos.»
- Los términos del protocolo se dejan como están (`forward`, `inverse`, `packetId`, `CC-ENV-1`) y se explican la primera vez.
- Sin alarmismo: las alertas de seguridad son firmes pero tranquilas («¡Alerta! La huella de EQ03 cambió. No se usará hasta que la aceptes de nuevo.»).
- Los textos de la interfaz no llevan emojis.

## 7. Aplicaciones

- **Interfaz web**: encabezado Azul Atalaya con el logotipo y la navegación; barra de estado fija con nodo, IP, puertos y oyente UDP.
- **Presentación y reporte**: portada con el logotipo centrado sobre blanco y el nombre debajo; diapositivas con banda superior Azul Atalaya.
- **Etiqueta de la laptop de la demo**: «Atalaya EQ08 · 5008 / 5108 · UDP 5099», con la huella abreviada (16 caracteres).

## 8. Aprobación

| Fecha | Decisión | Integrantes |
| --- | --- | --- |
| <!-- TODO: fecha --> | <!-- TODO: Aprobado / Cambios solicitados --> | <!-- TODO: integrantes --> |
