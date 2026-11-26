# ADR 0004 — Contraseña del PFX en variable de entorno

- **Estado:** Aceptada (plan §1)
- **Fecha:** 2026-11-26

## Contexto

La llave privada de identidad (§7) no debe salir del nodo ni guardarse en claro. El repositorio es público y no puede contener secretos.

## Decisión

La identidad se guarda en `data/identidad.pfx` (PKCS#12 con AES-256-CBC, PBKDF2-SHA256 de 100 000 iteraciones). La contraseña se lee de la variable de entorno **`CC_PFX_PASSWORD`** (clave de configuración `PFX_PASSWORD`) o, en desarrollo, de *user-secrets* (`dotnet user-secrets set PFX_PASSWORD ...` en `src/CentroCiber.Web`). Si falta, el nodo **no arranca** y lo explica. Nunca se lee de `appsettings*.json`.

## Consecuencias

- `*.pfx`, `*.p12`, `secrets*.json` y `.env` están en `.gitignore`.
- En Linux el PFX se crea con permisos `600`.
- Perder la contraseña obliga a borrar el PFX y regenerar la identidad (cambia la huella; los demás nodos verán la alerta de §6.3).
