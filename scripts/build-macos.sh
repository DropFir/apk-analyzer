#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$ROOT/.venv-build"
ADB="$(command -v adb || true)"
if [[ -z "$ADB" ]]; then
  for candidate in \
    "${ANDROID_SDK_ROOT:-}/platform-tools/adb" \
    "${ANDROID_HOME:-}/platform-tools/adb" \
    "$HOME/Library/Android/sdk/platform-tools/adb"; do
    if [[ -n "$candidate" && -f "$candidate" ]]; then
      ADB="$candidate"
      break
    fi
  done
fi
if [[ -z "$ADB" || ! -f "$ADB" ]]; then
  echo "adb was not found. Install official Android Platform Tools before building." >&2
  exit 1
fi

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
  --add-data "$ROOT/src/apkba_analyzer/assets:assets" \
  --add-binary "$ADB:platform-tools" \
  "$ROOT/main.py"

echo "Build complete: $ROOT/dist/APKBA-Analyzer.app"
