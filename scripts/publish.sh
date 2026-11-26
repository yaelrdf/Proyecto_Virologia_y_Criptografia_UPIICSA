#!/usr/bin/env bash
# Publica el nodo como aplicación autocontenida para Linux y Windows.
# Uso: scripts/publish.sh [linux-x64|win-x64|todos]   → carpeta publish/<rid>/
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-todos}"
rids=(linux-x64 win-x64)
[[ "$TARGET" != "todos" ]] && rids=("$TARGET")
for rid in "${rids[@]}"; do
  echo "[publicar] $rid"
  dotnet publish "$ROOT/src/CentroCiber.Web/CentroCiber.Web.csproj" -c Release -r "$rid" --self-contained true \
    -p:PublishSingleFile=false -o "$ROOT/publish/$rid"
  (cd "$ROOT/publish" && rm -f "centrociber-eq08-$rid.zip" && zip -qr "centrociber-eq08-$rid.zip" "$rid")
  echo "[publicar] listo: publish/$rid y publish/centrociber-eq08-$rid.zip"
done
