# Manual de instalación y configuración — Nodo EQ08

Este manual explica cómo instalar el nodo EQ08 en **Windows** y en **Linux**, abrir el firewall, arrancarlo, confirmar a los demás nodos y resolver los problemas más comunes.

## 1. Requisitos

| Recurso | Mínimo |
| --- | --- |
| Sistema | Windows 10/11 x64 o Linux x64 (Ubuntu 22.04+, Debian 12+, Fedora 39+) |
| Memoria y disco | 512 MB de RAM libres, 300 MB de disco más el espacio para los paquetes |
| Red | Misma LAN que los demás nodos; de preferencia un router o hotspot propio (las redes escolares suelen aislar clientes y bloquear broadcast) |
| Reloj | Sincronizado por NTP: la ventana de validación es de ±10 min |
| Puertos libres | TCP 5008 y 5108, UDP 5099 |
| Solo para compilar | .NET SDK 10.0 (`dotnet --list-sdks` debe mostrar `10.x`) |
| Solo para las pruebas de interoperabilidad | Python 3.10+ con `cryptography` y `pytest` |

## 2. Obtener el programa

### Opción A — versión publicada (recomendado para la demo)

Descarga la última versión de la pestaña *Releases* del repositorio y comprueba la suma con `SHA256SUMS.txt`. Ambos paquetes son **autocontenidos**: no necesitan .NET instalado.

| Sistema | Archivo | Cómo iniciarlo | Carpeta de datos |
| --- | --- | --- | --- |
| Linux x86_64 | `CentroCiber-EQ08-<versión>-x86_64.AppImage` | `chmod +x` y ejecutarlo (terminal o doble clic) | `~/.local/share/centrociber-eq08` |
| Windows x64 | `CentroCiber-EQ08-<versión>-win-x64.zip` | Descomprimir y doble clic en `Iniciar EQ08.cmd` | `data\` junto a `CentroCiber.Web.exe` |

Los lanzadores piden la contraseña del certificado si `CC_PFX_PASSWORD` no está definida (sección 3), fijan la raíz de contenido y abren `http://localhost:5008/`. Con `CC_NO_BROWSER=1` no abren el navegador y con `CC_Node__DataPath` se cambia la carpeta de datos.

- **Linux sin terminal:** la contraseña se pide con zenity o kdialog y un diálogo permite detener el nodo; el registro queda en `<datos>/logs/eq08.log`. Sin FUSE: `./CentroCiber-EQ08-*.AppImage --appimage-extract-and-run`.
- **Windows:** el ejecutable no está firmado; si SmartScreen avisa, usa «Más información» → «Ejecutar de todas formas». Cerrar la ventana detiene el nodo. También puede ejecutarse `CentroCiber.Web.exe` directamente desde su carpeta con `CC_PFX_PASSWORD` definida.

Las versiones se generan con `scripts/package-release.sh` (dejan los archivos en `dist/`) y se publican solas al empujar una etiqueta `vX.Y.Z` (flujo `.github/workflows/release.yml`). Los artefactos de cada ejecución de la CI (*Actions*) siguen disponibles como carpeta sin lanzador.

### Opción B — publicarlo tú

```bash
scripts/publish.sh            # Linux: genera publish/linux-x64 y publish/win-x64
```

```powershell
.\scripts\publish.ps1         # Windows
```

### Opción C — ejecutar desde el código (desarrollo)

```bash
dotnet run --project src/CentroCiber.Web
```

## 3. Contraseña del certificado (`CC_PFX_PASSWORD`)

En el primer arranque, el nodo genera su identidad: `data/identidad.pfx` (RSA-2048, `CN=EQ08`). El archivo va cifrado con la contraseña de la variable **`CC_PFX_PASSWORD`**. Sin esa variable, el nodo **no arranca**.

- Usa una contraseña larga y no la compartas por el chat del grupo.
- Usa la **misma** contraseña en cada arranque. Si la pierdes, borra `data/identidad.pfx` y define una nueva: la huella cambiará y los demás nodos tendrán que confirmarla otra vez.
- En desarrollo puedes usar *user-secrets*: `cd src/CentroCiber.Web && dotnet user-secrets set PFX_PASSWORD "..."`.

**Linux:**

```bash
export CC_PFX_PASSWORD='una-contraseña-larga'
```

**Windows (solo la sesión actual):**

```powershell
$env:CC_PFX_PASSWORD = "una-contraseña-larga"
```

**Windows (permanente para tu usuario):**

```powershell
[Environment]::SetEnvironmentVariable("CC_PFX_PASSWORD", "una-contraseña-larga", "User")
```

## 4. Firewall

Hay que abrir **TCP 5008** (API HTTP), **TCP 5108** (API HTTPS) y **UDP 5099** (anuncio).

### Windows

En PowerShell **como Administrador**, desde la carpeta del repositorio:

```powershell
.\scripts\firewall-windows.ps1 -Team 8 -Perfil Private
```

Equivalente con `netsh`:

```bat
netsh advfirewall firewall add rule name="CentroCiber HTTP EQ08" dir=in action=allow protocol=TCP localport=5008 profile=private
```

```bat
netsh advfirewall firewall add rule name="CentroCiber HTTPS EQ08" dir=in action=allow protocol=TCP localport=5108 profile=private
```

```bat
netsh advfirewall firewall add rule name="CentroCiber UDP 5099" dir=in action=allow protocol=UDP localport=5099 profile=private
```

Marca la red Wi-Fi o Ethernet como **Privada** en *Configuración → Red e Internet → Propiedades*. En una red «Pública», Windows bloquea el descubrimiento. La primera vez que arranque el nodo, Windows puede mostrar un aviso del firewall: permite el acceso en redes privadas.

### Linux (ufw)

```bash
sudo scripts/firewall-linux.sh 8                       # desde cualquier origen
```

```bash
sudo scripts/firewall-linux.sh 8 --subred 192.168.1.0/24   # solo desde la LAN
```

Con `firewalld` (Fedora):

```bash
sudo firewall-cmd --add-port=5008/tcp --add-port=5108/tcp --add-port=5099/udp --permanent && sudo firewall-cmd --reload
```

## 5. Primer arranque

**Linux (binario):**

```bash
cd ~/atalaya && ./CentroCiber.Web
```

**Windows (binario):**

```powershell
cd C:\Atalaya; .\CentroCiber.Web.exe
```

La consola mostrará `Now listening on: http://[::]:5008` y `https://[::]:5108`. Comprueba:

```bash
curl http://localhost:5008/api/status
```

Abre **http://localhost:5008** en el navegador (o `http://<IP-de-la-laptop>:5008` desde otra máquina de la LAN). En la barra inferior verás `EQ08`, la IP detectada, los puertos y «Oyente UDP activo».

Archivos que se crean en `data/` (junto al ejecutable):

| Archivo | Contenido |
| --- | --- |
| `identidad.pfx` | Certificado y llave privada, cifrados con `CC_PFX_PASSWORD` |
| `centrociber.db` | Base de datos SQLite (38 registros de semilla) |
| `paquetes/bandeja`, `paquetes/consultas` | Zips recibidos y guardados |

**Respalda `data/`** antes de la demo. **Nunca** la subas al repositorio.

### Configuración opcional

Todo lo de `appsettings.json` (sección `Node`) se puede sobrescribir con variables `CC_Node__...`. La lista completa está en el [README](../../README.md#variables-de-entorno). Ejemplos:

```bash
export CC_Node__AdvertisedIp=192.168.1.14     # forzar la IP anunciada si hay varias interfaces
```

```bash
export CC_Node__DataPath=/srv/atalaya/data    # otra carpeta de datos
```

## 6. Confirmar a los demás nodos (TOFU)

1. Entra a **Nodos**. Los nodos de la LAN aparecen solos por el anuncio UDP. Si no aparecen, usa **Buscar nodos** (escaneo de la /24 en los puertos 5001–5020) o **Alta manual** (IP y puerto, por ejemplo `192.168.1.21` y `5001`).
2. Cada nodo nuevo aparece como **Pendiente de confirmar**, con su **huella observada**.
3. **Compara la huella** con la que te dicte el otro equipo (la ven en su barra de estado o en *Ajustes*). Si coincide, pulsa **Confirmar huella**. Desde ese momento queda fijada.
4. Si después un nodo presenta otra huella, aparece una **alerta roja** y el nodo no se usa hasta que pulses **Aceptar nueva huella**. Hazlo solo si el otro equipo confirma que regeneró su certificado.

Solo los nodos **en línea y confirmados** se usan para delegar algoritmos y para reenviar paquetes.

## 7. HTTPS

- Está activo por omisión en el puerto **5108**, con el mismo certificado de identidad (§5.2). Se puede desactivar en *Ajustes* (requiere reinicio) o con `CC_Node__HttpsEnabled=false`.
- Cuando ambos nodos ofrecen HTTPS, EQ08 lo usa como cliente y **solo acepta el certificado cuya huella está fijada**. No valida una cadena de confianza, porque los certificados son autofirmados.
- El navegador mostrará una advertencia en `https://localhost:5108`, porque el certificado es autofirmado. Para la interfaz basta HTTP en la LAN.

## 8. Solución de problemas

| Síntoma | Causa probable | Solución |
| --- | --- | --- |
| `Falta la contraseña del certificado` al arrancar | No está definida `CC_PFX_PASSWORD` | Defínela (sección 3) en la misma terminal |
| `The specified network password is not correct` / error al abrir el PFX | Contraseña distinta a la del primer arranque | Usa la contraseña original o borra `data/identidad.pfx` (la huella cambiará) |
| `El PFX pertenece a EQ08 pero el nodo está configurado como EQ09` | Dos nodos comparten la carpeta `data` | Usa `CC_Node__DataPath` distinto para cada uno |
| `Failed to bind to address ... 5008: address already in use` | Otro proceso usa el puerto (otra instancia) | Ciérralo; en Linux `ss -ltnp \| grep 5008`; en Windows `netstat -ano \| findstr 5008` y `taskkill /PID <pid>` |
| Los nodos no aparecen en **Nodos** | La red bloquea broadcast o aísla clientes, o el firewall bloquea UDP 5099 | Abre el firewall (sección 4), marca la red como Privada, usa **Buscar nodos** o **Alta manual**; de preferencia usa un router o hotspot propio |
| Aparecen, pero queda «Sin respuesta de status/certificate» | Firewall de la otra máquina, o IP anunciada incorrecta (varias interfaces, VPN) | Abre TCP 5000+n en la otra máquina; fija `CC_Node__AdvertisedIp` |
| `E-TIMESTAMP` al recibir o delegar | Relojes desfasados más de 10 min | Activa la hora automática (NTP) en ambas máquinas y compara `serverTimeUtc` en `/api/status` |
| `E-CERT-UNTRUSTED` | El otro nodo regeneró su certificado | Verifica con su equipo y acepta la nueva huella en **Nodos** |
| Algoritmo «no disponible» en Operar | El dueño no está en el directorio, está fuera de línea o su huella no está confirmada | Sigue el motivo que muestra la pantalla |
| `E-PARAMS` con HMAC | Clave de menos de 32 bytes o no Base64 | Usa **Generar clave** |
| La interfaz responde 403 | Entraste desde una IP que no es privada | Usa la IP de la LAN; para pruebas, `CC_Node__UiLanOnly=false` |
| La interfaz se ve sin estilos | Se ejecutó desde `bin/` de una versión anterior | Usa el binario publicado o actualiza a la versión actual |

## 9. Dos nodos en una sola máquina (demo o pruebas)

```bash
CC_PFX_PASSWORD=demo scripts/run-two-nodes.sh
```

```powershell
$env:CC_PFX_PASSWORD="demo"; .\scripts\run-two-nodes.ps1
```

Levanta EQ08 (5008/5108) y EQ09 (5009/5109), con carpetas de datos separadas. Ambos comparten el puerto UDP 5099 y se descubren solos. Para simular a EQ01 con AESGCM:

```bash
dotnet run --project tools/CentroCiber.MockNode -- --port 5001
```

## 10. Verificación manual pendiente

No se pudo comprobar en el entorno de desarrollo en la nube (Linux sin LAN real). El equipo debe hacerlo y anotarlo en el [backlog](../backlog/Backlog.md):

- [ ] Instalar el binario `win-x64` en una laptop Windows real, abrir el firewall con el script y arrancar.
- [ ] Descubrimiento por broadcast entre una laptop Windows y una Linux en el mismo router (en la CI de Windows solo se prueba en loopback).
- [ ] Recorrido completo Operar → enviar a bandeja → Aceptar → Consultas → `inverse` entre dos máquinas.
- [ ] Delegar al menos un algoritmo de cada equipo real (matriz de interoperabilidad).
- [ ] Que una persona ajena al equipo instale el nodo siguiendo este manual (criterio de la fase 9).
