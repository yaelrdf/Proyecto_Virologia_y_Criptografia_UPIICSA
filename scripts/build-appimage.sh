#!/usr/bin/env bash
# Construye la AppImage de Linux: scripts/build-appimage.sh [versión] [carpeta-salida]
# Requiere .NET SDK 10, desktop-file-utils (desktop-file-validate) y acceso a GitHub para descargar appimagetool.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-dev}"
OUT="${2:-$ROOT/publish}"
WORK="$(mktemp -d)"
APPDIR="$WORK/AppDir"
TOOL_VERSION="1.9.1"

echo "[appimage] Publicando linux-x64 autocontenido..."
dotnet publish "$ROOT/src/CentroCiber.Web/CentroCiber.Web.csproj" -c Release -r linux-x64 --self-contained true \
  -p:PublishSingleFile=false -o "$APPDIR/usr/lib/atalaya-eq08" --nologo -v quiet

install -m 755 "$ROOT/packaging/linux/AppRun" "$APPDIR/AppRun"
install -m 644 "$ROOT/packaging/linux/atalaya-eq08.desktop" "$APPDIR/atalaya-eq08.desktop"
install -m 644 "$ROOT/docs/assets/logo.svg" "$APPDIR/atalaya-eq08.svg"
ln -sf atalaya-eq08.svg "$APPDIR/.DirIcon"

TOOL="$WORK/appimagetool"
if ! curl -fsSL -o "$TOOL" "https://github.com/AppImage/appimagetool/releases/download/${TOOL_VERSION}/appimagetool-x86_64.AppImage"; then
  echo "[appimage] appimagetool ${TOOL_VERSION} no disponible; usando 'continuous'"
  curl -fsSL -o "$TOOL" "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
fi
chmod +x "$TOOL"

mkdir -p "$OUT"
TARGET="$OUT/Atalaya-EQ08-${VERSION}-x86_64.AppImage"
# Sin FUSE (CI, contenedores): appimagetool se ejecuta extrayéndose.
APPIMAGE_EXTRACT_AND_RUN=1 ARCH=x86_64 "$TOOL" --no-appstream "$APPDIR" "$TARGET"
rm -rf "$WORK"
echo "[appimage] Listo: $TARGET"
