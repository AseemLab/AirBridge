#!/usr/bin/env bash
# AirBridge launcher: creates a local venv on first run, installs
# dependencies if missing, then starts the server.
# Any arguments are forwarded to server.py, e.g.:
#   ./run.sh --port 9000 --out ~/Pictures/Incoming
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

VENV=".venv"
STAMP="$VENV/.deps-installed"

# Pick a python3 (>=3.9)
if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 not found. Install it with your package manager." >&2
  echo "  Debian/Ubuntu:  sudo apt install python3 python3-venv" >&2
  echo "  Fedora/RHEL  :  sudo dnf install python3" >&2
  echo "  Arch         :  sudo pacman -S python" >&2
  exit 1
fi

# Create the venv if it doesn't exist yet.
if [ ! -d "$VENV" ]; then
  echo "▸ creating virtual environment in $VENV"
  if ! python3 -m venv "$VENV" 2>/dev/null; then
    echo "error: 'python3 -m venv' failed. On Debian/Ubuntu you may need:" >&2
    echo "         sudo apt install python3-venv" >&2
    exit 1
  fi
fi

# shellcheck disable=SC1091
source "$VENV/bin/activate"

# Install / refresh dependencies when requirements.txt is newer than the stamp.
if [ ! -f "$STAMP" ] || [ requirements.txt -nt "$STAMP" ]; then
  echo "▸ installing dependencies"
  python -m pip install --quiet --upgrade pip
  python -m pip install --quiet -r requirements.txt
  touch "$STAMP"
fi

exec python server.py "$@"
