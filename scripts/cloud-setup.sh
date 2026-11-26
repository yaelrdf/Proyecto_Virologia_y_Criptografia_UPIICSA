#!/usr/bin/env bash
# =============================================================================
# Setup script — Claude Code (entorno en la nube) · Nodo EQ08
#
# Uso: pegar este archivo completo en el campo "Setup script" del entorno
# de Claude Code en la nube (claude.ai/code → entorno → Setup script).
# También puede ejecutarse a mano en Ubuntu 24.04:  sudo bash scripts/cloud-setup.sh
#
# Requisitos del entorno:
#   - Acceso de red "Trusted" (incluye archive.ubuntu.com, nuget.org, dot.net,
#     packages.microsoft.com y PyPI).
#   - El script corre como root en Ubuntu 24.04, antes de que arranque Claude Code.
#   - Debe terminar en ~5 min para que el entorno se guarde en caché y
#     DEBE salir con código 0 (si no, la sesión no inicia).
#
# Instala: .NET 10 SDK (LTS), dotnet-ef 10, sqlite3, zip/unzip, openssl,
#          netcat/socat (pruebas UDP/HTTP), librería Python "cryptography"
#          (pruebas de interoperabilidad) y restaura paquetes NuGet si ya
#          existe la solución en el repositorio.
# =============================================================================
set -uo pipefail

log()  { echo "[setup-eq08] $*"; }
warn() { echo "[setup-eq08][AVISO] $*" >&2; }

export DEBIAN_FRONTEND=noninteractive
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1

DOTNET_MAJOR=10
EF_VERSION="10.*"
START=$(date +%s)

# -----------------------------------------------------------------------------
# 1. Paquetes del sistema (en paralelo con la descarga de .NET no es posible:
#    apt usa un candado, así que se instalan juntos en una sola llamada).
# -----------------------------------------------------------------------------
log "Actualizando índices de apt..."
apt-get update -y -qq || warn "apt-get update falló; se intentará continuar"

SYS_PKGS=(sqlite3 zip unzip openssl netcat-openbsd socat iproute2 ca-certificates curl)

have_dotnet10() { command -v dotnet >/dev/null 2>&1 && dotnet --list-sdks 2>/dev/null | grep -q "^${DOTNET_MAJOR}\."; }

if have_dotnet10; then
  log ".NET ${DOTNET_MAJOR} SDK ya instalado; solo utilidades del sistema."
  apt-get install -y -qq --no-install-recommends "${SYS_PKGS[@]}" || warn "Falló la instalación de utilidades"
else
  log "Instalando .NET ${DOTNET_MAJOR} SDK (archivo de Ubuntu) + utilidades..."
  if ! apt-get install -y -qq --no-install-recommends "dotnet-sdk-${DOTNET_MAJOR}.0" "${SYS_PKGS[@]}"; then
    warn "apt no pudo instalar dotnet-sdk-${DOTNET_MAJOR}.0; probando con dotnet-install.sh"
    apt-get install -y -qq --no-install-recommends "${SYS_PKGS[@]}" || true
    if curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh; then
      bash /tmp/dotnet-install.sh --channel "${DOTNET_MAJOR}.0" --install-dir /usr/share/dotnet \
        && ln -sf /usr/share/dotnet/dotnet /usr/bin/dotnet \
        || warn "dotnet-install.sh falló (¿dominio de descarga fuera de la lista permitida?)"
    else
      warn "No se pudo descargar dotnet-install.sh"
    fi
  fi
fi

if have_dotnet10; then
  log "SDKs disponibles:"; dotnet --list-sdks
else
  warn ".NET ${DOTNET_MAJOR} NO quedó instalado. Revisa el acceso de red del entorno (debe ser Trusted)."
fi

# -----------------------------------------------------------------------------
# 2. Variables de entorno persistentes para todas las shells de la sesión
# -----------------------------------------------------------------------------
PROFILE_SNIPPET='# --- EQ08 .NET ---
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export ASPNETCORE_ENVIRONMENT=${ASPNETCORE_ENVIRONMENT:-Development}
case ":$PATH:" in *":$HOME/.dotnet/tools:"*) ;; *) export PATH="$PATH:$HOME/.dotnet/tools" ;; esac
# --- fin EQ08 ---'

echo "$PROFILE_SNIPPET" > /etc/profile.d/eq08-dotnet.sh
chmod 644 /etc/profile.d/eq08-dotnet.sh
for rc in /root/.bashrc /etc/bash.bashrc; do
  if [ -f "$rc" ] && ! grep -q "EQ08 .NET" "$rc"; then
    printf '\n%s\n' "$PROFILE_SNIPPET" >> "$rc"
  fi
done
export PATH="$PATH:$HOME/.dotnet/tools"
log "Variables de entorno configuradas (/etc/profile.d/eq08-dotnet.sh)."

# -----------------------------------------------------------------------------
# 3. Herramientas en paralelo: dotnet-ef y librería Python para interop
# -----------------------------------------------------------------------------
(
  if have_dotnet10; then
    if dotnet tool list --global 2>/dev/null | grep -qi "dotnet-ef"; then
      dotnet tool update --global dotnet-ef --version "$EF_VERSION" >/dev/null 2>&1 || true
    else
      dotnet tool install --global dotnet-ef --version "$EF_VERSION" \
        && log "dotnet-ef instalado." || warn "No se pudo instalar dotnet-ef"
    fi
  fi
) &
PID_EF=$!

(
  if python3 -c "import cryptography" 2>/dev/null; then
    log "Python 'cryptography' ya disponible."
  else
    pip install --quiet --break-system-packages cryptography \
      && log "Python 'cryptography' instalado." || warn "No se pudo instalar 'cryptography'"
  fi
) &
PID_PY=$!

wait "$PID_EF" || true
wait "$PID_PY" || true

# -----------------------------------------------------------------------------
# 4. Pre-restaurar NuGet si la solución ya existe (queda en la caché del entorno)
# -----------------------------------------------------------------------------
if have_dotnet10; then
  for base in "${CLAUDE_PROJECT_DIR:-}" "$PWD" /home/user /root /workspace; do
    [ -n "$base" ] && [ -d "$base" ] || continue
    SLN=$(find "$base" -maxdepth 3 \( -name "*.slnx" -o -name "*.sln" \) -not -path "*/node_modules/*" 2>/dev/null | head -n 1)
    if [ -n "$SLN" ]; then
      log "Restaurando paquetes de $SLN ..."
      timeout 150 dotnet restore "$SLN" --nologo -v q \
        && log "Restauración completa." || warn "dotnet restore falló o excedió el tiempo; se hará en la sesión"
      break
    fi
  done
fi

# -----------------------------------------------------------------------------
# 5. Resumen
# -----------------------------------------------------------------------------
log "Resumen de herramientas:"
{ command -v dotnet >/dev/null && echo "  dotnet  : $(dotnet --version 2>/dev/null)"; } || echo "  dotnet  : NO INSTALADO"
{ [ -x "$HOME/.dotnet/tools/dotnet-ef" ] && echo "  dotnet-ef: $("$HOME/.dotnet/tools/dotnet-ef" --version 2>/dev/null | tail -n 1)"; } || echo "  dotnet-ef: no instalado"
echo "  sqlite3 : $(sqlite3 --version 2>/dev/null | cut -d' ' -f1)"
echo "  openssl : $(openssl version 2>/dev/null)"
echo "  python  : $(python3 --version 2>/dev/null)"
log "Terminado en $(( $(date +%s) - START )) s."

exit 0
