#!/usr/bin/env bash
# Builds the release artifacts of the EQ08 node in dist/:
#   CentroCiber-EQ08-<versión>-x86_64.AppImage   (Linux, autocontenido)
#   CentroCiber-EQ08-<versión>-win-x64.zip       (Windows portátil: CentroCiber.Web.exe + «Iniciar EQ08.cmd»)
#   SHA256SUMS.txt
# Uso: scripts/package-release.sh [versión]   (por defecto, <Version> de Directory.Build.props)
# Variables: APPIMAGETOOL=<ruta> para usar un appimagetool ya descargado.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' "$ROOT/Directory.Build.props")}"
VERSION="${VERSION#v}"
NAME="CentroCiber-EQ08-$VERSION"
WORK="$ROOT/publish/release"
DIST="$ROOT/dist"
PROJECT="$ROOT/src/CentroCiber.Web/CentroCiber.Web.csproj"

# Pinned appimagetool (https://github.com/AppImage/appimagetool/releases/tag/1.9.1).
APPIMAGETOOL_URL="https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage"
APPIMAGETOOL_SHA256="ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"

rm -rf "$WORK" "$DIST"
mkdir -p "$WORK" "$DIST"

publish() { # $1 = rid, $2 = output folder
  echo "[release] dotnet publish $1 ($VERSION)"
  dotnet publish "$PROJECT" -c Release -r "$1" --self-contained true \
    -p:PublishSingleFile=false -p:Version="$VERSION" -p:DebugType=None -p:DebugSymbols=false \
    -o "$2"
}

# ---------- Windows: portable zip ----------
WIN_DIR="$WORK/$NAME-win-x64"
publish win-x64 "$WIN_DIR"
cp "$ROOT/packaging/windows/iniciar-eq08.ps1" "$ROOT/packaging/windows/Iniciar EQ08.cmd" "$WIN_DIR/"
cp "$ROOT/LICENSE" "$WIN_DIR/LICENSE.txt"
cp "$ROOT/packaging/LEEME.txt" "$WIN_DIR/LEEME.txt"
(cd "$WORK" && zip -qr "$DIST/$NAME-win-x64.zip" "$NAME-win-x64")

# ---------- Linux: AppImage ----------
APPDIR="$WORK/AppDir"
publish linux-x64 "$APPDIR/usr/lib/centrociber-eq08"
cp "$ROOT/LICENSE" "$APPDIR/usr/lib/centrociber-eq08/LICENSE.txt"
cp "$ROOT/packaging/LEEME.txt" "$APPDIR/usr/lib/centrociber-eq08/LEEME.txt"
install -m 755 "$ROOT/packaging/linux/AppRun" "$APPDIR/AppRun"
install -m 644 "$ROOT/packaging/linux/centrociber-eq08.desktop" "$APPDIR/centrociber-eq08.desktop"
install -m 644 "$ROOT/packaging/linux/centrociber-eq08.png" "$APPDIR/centrociber-eq08.png"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"
cp "$APPDIR/centrociber-eq08.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/"
ln -sf centrociber-eq08.png "$APPDIR/.DirIcon"

TOOL="${APPIMAGETOOL:-}"
if [[ -z "$TOOL" ]]; then
  TOOL="$WORK/appimagetool-x86_64.AppImage"
  echo "[release] descargando appimagetool 1.9.1"
  curl -fsSL -o "$TOOL" "$APPIMAGETOOL_URL"
  echo "$APPIMAGETOOL_SHA256  $TOOL" | sha256sum -c --quiet -
  chmod +x "$TOOL"
fi
# APPIMAGE_EXTRACT_AND_RUN: works without FUSE (CI runners, containers).
APPIMAGE_EXTRACT_AND_RUN=1 ARCH=x86_64 "$TOOL" --no-appstream "$APPDIR" "$DIST/$NAME-x86_64.AppImage"
chmod +x "$DIST/$NAME-x86_64.AppImage"

(cd "$DIST" && sha256sum -- * > SHA256SUMS.txt)
echo "[release] listo:"
ls -lh "$DIST"
