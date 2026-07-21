#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$ROOT/.venv-build"

if [[ ! -d "$VENV" ]]; then
  python3 -m venv "$VENV"
fi

"$VENV/bin/python" -m pip install --upgrade pip
"$VENV/bin/python" -m pip install -e "$ROOT[dev]"
"$VENV/bin/python" -m PyInstaller \
  --noconfirm \
  --clean \
  --windowed \
  --onedir \
  --name 'APKBA-Analyzer' \
  --paths "$ROOT/src" \
  --collect-data androguard \
  --hidden-import androguard.core.apk \
  "$ROOT/main.py"

echo "Build complete: $ROOT/dist/APKBA-Analyzer.app"
