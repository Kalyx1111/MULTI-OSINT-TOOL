#!/usr/bin/env bash
# MULTI-OSINT-TOOL launcher for Linux and macOS.
# Creates a private Python environment inside this folder (no system-wide changes), then starts the app.
set -u
cd "$(dirname "$0")" || exit 1

pause() { printf '\n'; read -r -p "Press Enter to exit..." _ || true; }

PY=""
for c in python3.13 python3.12 python3.11 python3.10 python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
    PY="$c"; break
  fi
done
if [ -z "$PY" ]; then
  echo "Python 3.10 or newer is required. Install it from https://www.python.org/downloads/ or your package manager."
  pause; exit 1
fi

if [ ! -x ".mot_venv/bin/python" ]; then
  echo "Creating a private environment in .mot_venv (no network needed) ..."
  if ! "$PY" -m venv .mot_venv; then
    echo "Could not create the environment. On Debian/Ubuntu run: sudo apt install python3-venv"
    pause; exit 1
  fi
fi

# mot_main.py installs missing packages (offline bundle first, with integrity check), then runs the app.
# It keeps the window open itself, so no second prompt here.
exec .mot_venv/bin/python mot_main.py "$@"
