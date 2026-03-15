#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Requesting sudo elevation for Shield Stopper..."
  exec sudo bash "$0" "$@"
fi

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
else
  PYTHON_BIN="python"
fi

if [[ $# -eq 0 ]]; then
  echo "Starting Shield Stopper watchdog..."
  exec "$PYTHON_BIN" "$ROOT_DIR/shield_launcher.py" start --config "$ROOT_DIR/config.json"
fi

echo "Running Shield Stopper mode: $*"
exec "$PYTHON_BIN" "$ROOT_DIR/shield_launcher.py" "$@"
