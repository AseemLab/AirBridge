#!/usr/bin/env bash
# Builds a .deb package from the current server.py. Run from anywhere;
# paths are resolved relative to this script's location.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="${1:-$REPO_ROOT/dist}"

VERSION=$(grep -Po '(?<=^VERSION = ")[^"]+' "$REPO_ROOT/server.py")
ARCH=all
PKG_DIR=$(mktemp -d)
trap 'rm -rf "$PKG_DIR"' EXIT

install -Dm755 "$REPO_ROOT/server.py" "$PKG_DIR/usr/lib/airbridge/server.py"
install -Dm755 "$SCRIPT_DIR/airbridge.wrapper" "$PKG_DIR/usr/bin/airbridge"
install -Dm644 "$SCRIPT_DIR/../airbridge.desktop" "$PKG_DIR/usr/share/applications/airbridge.desktop"
install -Dm644 "$SCRIPT_DIR/../icons/airbridge-256.png" "$PKG_DIR/usr/share/pixmaps/airbridge.png"
for sz in 16 32 48 64 128 256 512; do
  install -Dm644 "$SCRIPT_DIR/../icons/airbridge-${sz}.png" \
    "$PKG_DIR/usr/share/icons/hicolor/${sz}x${sz}/apps/airbridge.png"
done
install -Dm644 "$REPO_ROOT/LICENSE" "$PKG_DIR/usr/share/doc/airbridge/copyright"
install -Dm644 "$REPO_ROOT/README.md" "$PKG_DIR/usr/share/doc/airbridge/README.md"

mkdir -p "$PKG_DIR/DEBIAN"
sed "s/__VERSION__/$VERSION/" "$SCRIPT_DIR/control.template" > "$PKG_DIR/DEBIAN/control"

mkdir -p "$OUT_DIR"
OUT_FILE="$OUT_DIR/airbridge_${VERSION}-1_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$PKG_DIR" "$OUT_FILE"
echo "built: $OUT_FILE"
