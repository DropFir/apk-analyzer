"""Development and packaged-application entry point."""

from __future__ import annotations

import os
import sys
from pathlib import Path

_NULL_STREAMS = []
for stream_name in ("stdout", "stderr"):
    if getattr(sys, stream_name) is None:
        stream = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115
        _NULL_STREAMS.append(stream)
        setattr(sys, stream_name, stream)

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from apkba_analyzer.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
