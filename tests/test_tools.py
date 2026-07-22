from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from apkba_analyzer.tools import _subprocess_creation_flags, run_tool


def test_windows_creation_flags_hide_console_window() -> None:
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        assert _subprocess_creation_flags() == subprocess.CREATE_NO_WINDOW
    else:
        assert _subprocess_creation_flags() == 0


def test_run_tool_passes_creation_flags_to_subprocess() -> None:
    with (
        patch("apkba_analyzer.tools._subprocess_creation_flags", return_value=1234),
        patch("apkba_analyzer.tools.subprocess.run") as mocked_run,
    ):
        run_tool(Path("helper.exe"), ["--version"])

    assert mocked_run.call_args.kwargs["creationflags"] == 1234
