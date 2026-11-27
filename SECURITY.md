# Política de seguridad

El nodo EQ08 es un **proyecto académico** para una red local de pruebas. No está pensado para producción ni para Internet. Aun así, tomamos en serio los fallos de seguridad.

## Cómo reportar una vulnerabilidad

- **No abras un issue público** con detalles explotables.
- Usa el aviso privado de GitHub (*Security → Report a vulnerability*) del repositorio o escribe a un integrante del equipo. <!-- TODO: integrantes — correo de contacto de seguridad -->
- Incluye: versión o commit, pasos para reproducir, impacto esperado y, si la tienes, una propuesta de corrección.
- Respondemos en un máximo de 5 días hábiles durante el semestre.

## Alcance

Dentro del alcance: la API REST (`/api/*`), la validación de paquetes (§13.1), los sobres `CC-ENV-1`, la firma RSA-PSS, el descubrimiento y la confianza (TOFU), el filtro solo-LAN de la interfaz y el manejo de secretos.

Fuera del alcance: ataques de denegación de servicio volumétricos en la LAN, ataques físicos a las máquinas de la demo e ingeniería social.

## Manejo del PFX y de las contraseñas

- La identidad del nodo es `data/identidad.pfx` (RSA-2048), protegido con la contraseña de **`CC_PFX_PASSWORD`** (o *user-secrets* en desarrollo). Nunca va en `appsettings*.json`, en la base de datos ni en el repositorio.
- En Linux el PFX se crea con permisos `600`. En Windows, guarda la carpeta `data` en un perfil de usuario no compartido.
- Si sospechas que el PFX o su contraseña se filtraron, detén el nodo, borra `data/identidad.pfx`, define una contraseña nueva y vuelve a arrancar. La huella cambiará y los demás nodos tendrán que confirmarla de nuevo (§6.3). Avísales.
- Las claves de algoritmos (por ejemplo, la clave HMAC) llegan dentro de sobres `CC-ENV-1`, se usan y se borran de memoria. **Nunca** se guardan ni se registran en bitácoras, URL, encabezados ni `manifest.json`.

## Lo que nunca debe subirse al repositorio

- `*.pfx`, `*.p12`, llaves privadas reales, contraseñas, `.env`, `secrets*.json`.
- Bases de datos (`*.db`) ni la carpeta `data/` o `storage/`.
- Paquetes recibidos de otros equipos.

`.gitignore` cubre estos casos. La **única** excepción es `vectores/EQ08/privada-PRUEBA.pem`: una llave **solo de prueba**, generada para los vectores públicos, que no es la identidad real del nodo.

## Controles implementados

- Las comparaciones de hash, MAC, huella y firma usan `CryptographicOperations.FixedTimeEquals`.
- Los zips se leen en memoria, con validación de nombres (sin rutas, `..` ni ocultos), del número de entradas, del tamaño descomprimido (≤ 200 MB) y de la razón de compresión (≤ 100:1).
- Anti-repetición por `packetId` y `requestId`, y ventana de ±10 min.
- HTTPS hacia otros nodos solo si la huella del certificado TLS coincide con la fijada.
- La interfaz web solo responde a IP privadas o de loopback.
- Límite de 10 peticiones criptográficas simultáneas (`E-BUSY`).
