#!/usr/bin/env bash
# Builds a self-contained AirBridge AppImage for x86_64 Linux.
#
# The AppImage bundles its own CPython (from astral-sh/python-build-standalone)
# plus cryptography/qrcode built for the manylinux2014 (glibc >= 2.17) tag, so
# the result runs on essentially any x86_64 Linux from the last decade+
# without depending on the host's Python version or installed packages.
#
# Notes for future maintainers:
#  - Do NOT `strip` the bundled python3.12 binary or its .so files: this
#    particular standalone build breaks ("no version information available")
#    under both `strip --strip-unneeded` and `strip --strip-debug`. Squashfs
#    compression alone gets the ~350MB tree down to ~105MB, which is fine.
#  - pip on the build machine will default to whatever manylinux tag matches
#    *this* machine's glibc, which may be newer/narrower than what we want to
#    ship. We explicitly download the manylinux2014 (abi3) wheel so the result
#    works on old and new distros alike, regardless of what this build host is.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="${1:-$REPO_ROOT/dist}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

CPYTHON_RELEASE="20260623"
CPYTHON_VERSION="3.12.13"
CPYTHON_URL="https://github.com/astral-sh/python-build-standalone/releases/download/${CPYTHON_RELEASE}/cpython-${CPYTHON_VERSION}%2B${CPYTHON_RELEASE}-x86_64-unknown-linux-gnu-install_only.tar.gz"
APPIMAGETOOL_URL="https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage"

APPDIR="$WORK/AirBridge.AppDir"
mkdir -p "$APPDIR/usr/share/airbridge"

echo "== fetching standalone CPython =="
curl -sL -o "$WORK/cpython.tar.gz" "$CPYTHON_URL"
mkdir -p "$APPDIR/usr"
tar -xzf "$WORK/cpython.tar.gz" -C "$APPDIR/usr"
mv "$APPDIR/usr/python" "$APPDIR/usr/pyruntime"
PYBIN="$APPDIR/usr/pyruntime/bin/python3"

echo "== installing broadly-compatible (manylinux2014) wheels =="
mkdir -p "$WORK/wheels"
"$PYBIN" -m pip download --no-deps --only-binary=:all: \
  --platform manylinux2014_x86_64 --python-version 312 --implementation cp --abi abi3 \
  -d "$WORK/wheels" "cryptography>=42"
"$PYBIN" -m pip download --no-deps --only-binary=:all: \
  --platform manylinux2014_x86_64 --python-version 312 --implementation cp --abi cp312 \
  -d "$WORK/wheels" cffi
"$PYBIN" -m pip install --no-cache-dir --no-index --no-deps --find-links "$WORK/wheels" cryptography cffi
"$PYBIN" -m pip install --no-cache-dir --no-deps "qrcode>=7.4" pycparser

echo "== verifying import =="
"$PYBIN" -c "import cryptography, qrcode; from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print('cryptography', cryptography.__version__, 'OK')"

echo "== trimming unused stdlib/tooling =="
PYLIB="$APPDIR/usr/pyruntime/lib/python3.12"
rm -rf "$PYLIB/test" "$PYLIB/idlelib" "$PYLIB/lib2to3" "$PYLIB/tkinter" \
       "$APPDIR"/usr/pyruntime/lib/libtk* "$APPDIR"/usr/pyruntime/lib/libtcl* \
       "$APPDIR/usr/pyruntime/share/tcltk" \
       "$PYLIB/site-packages/pip" \
       "$APPDIR"/usr/pyruntime/lib/python3.12/config-3.12-*/lib*.a
rm -f "$APPDIR"/usr/pyruntime/bin/pip* "$APPDIR"/usr/pyruntime/bin/2to3* \
      "$APPDIR"/usr/pyruntime/bin/pydoc3* "$APPDIR"/usr/pyruntime/bin/python3.12-config \
      "$APPDIR"/usr/pyruntime/bin/python3-config "$APPDIR"/usr/pyruntime/bin/cffi-gen-src \
      "$APPDIR"/usr/pyruntime/bin/qr "$APPDIR"/usr/pyruntime/bin/idle3*
find "$APPDIR/usr/pyruntime" -iname "__pycache__" -type d -prune -exec rm -rf {} +

echo "== assembling AppDir =="
cp "$REPO_ROOT/server.py" "$APPDIR/usr/share/airbridge/server.py"
cp "$SCRIPT_DIR/../airbridge.desktop" "$APPDIR/airbridge.desktop"
cp "$SCRIPT_DIR/../icons/airbridge-256.png" "$APPDIR/airbridge.png"
install -m755 "$SCRIPT_DIR/AppRun" "$APPDIR/AppRun"

echo "== fetching appimagetool =="
curl -sL -o "$WORK/appimagetool" "$APPIMAGETOOL_URL"
chmod +x "$WORK/appimagetool"
( cd "$WORK" && ./appimagetool --appimage-extract >/dev/null )

mkdir -p "$OUT_DIR"
ARCH=x86_64 "$WORK/squashfs-root/AppRun" "$APPDIR" "$OUT_DIR/AirBridge-x86_64.AppImage"
echo "built: $OUT_DIR/AirBridge-x86_64.AppImage"
