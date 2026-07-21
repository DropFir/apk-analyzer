#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  python3 -m venv "$ROOT/.venv"
  "$PYTHON" -m pip install -e "$ROOT"
fi
"$PYTHON" "$ROOT/main.py"
