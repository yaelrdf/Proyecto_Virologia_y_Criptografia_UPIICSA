#!/usr/bin/env bash
# Levanta dos nodos locales para la demo: EQ08 (5008/5108) y un segundo nodo EQ09 (5009/5109).
# Ambos comparten el puerto UDP 5099 (ReuseAddress) y se descubren por broadcast.
#
# Uso:  CC_PFX_PASSWORD=<contraseña> scripts/run-two-nodes.sh [carpeta-datos]
# Detener: Ctrl+C (envía el anuncio "offline" y cierra ambos).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="${1:-$ROOT/data/demo}"
: "${CC_PFX_PASSWORD:?Define CC_PFX_PASSWORD con la contraseña de los PFX de prueba}"

echo "[demo] Compilando..."
dotnet build "$ROOT/src/CentroCiber.Web" -c Release -v quiet -nologo >/dev/null
DLL="$ROOT/src/CentroCiber.Web/bin/Release/net10.0/CentroCiber.Web.dll"

start_node() {
  local team="$1" http="$2" https="$3"
  CC_Node__TeamNumber="$team" CC_Node__HttpPort="$http" CC_Node__HttpsPort="$https" \
  CC_Node__DataPath="$DATA/EQ$(printf %02d "$team")" ASPNETCORE_ENVIRONMENT=Development \
  dotnet "$DLL" --contentRoot "$ROOT/src/CentroCiber.Web" &
}

start_node 8 5008 5108; PID_A=$!
start_node 9 5009 5109; PID_B=$!
trap 'echo "[demo] Deteniendo..."; kill $PID_A $PID_B 2>/dev/null; wait' INT TERM EXIT

echo "[demo] EQ08 → http://localhost:5008  (interfaz y API)"
echo "[demo] EQ09 → http://localhost:5009"
echo "[demo] Datos en $DATA. Ctrl+C para detener."
wait
