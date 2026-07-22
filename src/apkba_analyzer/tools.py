"""Discovery and safe invocation of optional Android SDK tools."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Iterable
from pathlib import Path


def _subprocess_creation_flags() -> int:
    """Prevent SDK helper tools from opening console windows on Windows."""

    if os.name == "nt":
        return subprocess.CREATE_NO_WINDOW
    return 0


def _first_existing(candidates: Iterable[Path | None]) -> Path | None:
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate.resolve()
    return None


def find_apkanalyzer() -> Path | None:
    command = shutil.which("apkanalyzer") or shutil.which("apkanalyzer.bat")
    candidates: list[Path | None] = [Path(command) if command else None]
    for key in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        raw = os.environ.get(key)
        if not raw:
            continue
        root = Path(raw)
        candidates.extend(
            [
                root / "cmdline-tools" / "latest" / "bin" / "apkanalyzer.bat",
                root / "cmdline-tools" / "latest" / "bin" / "apkanalyzer",
                root / "tools" / "bin" / "apkanalyzer.bat",
                root / "tools" / "bin" / "apkanalyzer",
            ]
        )
    candidates.extend(
        [
            Path.home()
            / "Library"
            / "Android"
            / "sdk"
            / "cmdline-tools"
            / "latest"
            / "bin"
            / "apkanalyzer",
            Path.home()
            / "AppData"
            / "Local"
            / "Android"
            / "Sdk"
            / "cmdline-tools"
            / "latest"
            / "bin"
            / "apkanalyzer.bat",
        ]
    )
    return _first_existing(candidates)


def _sdk_roots(apkanalyzer: Path | None) -> list[Path]:
    roots: list[Path] = []
    for key in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        raw = os.environ.get(key)
        if raw:
            roots.append(Path(raw))
    if apkanalyzer:
        # <sdk>/cmdline-tools/<version>/bin/apkanalyzer
        parents = apkanalyzer.parents
        if len(parents) >= 4:
            roots.append(parents[3])
    roots.extend(
        [
            Path.home() / "Library" / "Android" / "sdk",
            Path.home() / "AppData" / "Local" / "Android" / "Sdk",
        ]
    )
    unique: list[Path] = []
    for root in roots:
        resolved = root.expanduser()
        if resolved not in unique:
            unique.append(resolved)
    return unique


def find_apksigner(apkanalyzer: Path | None = None) -> Path | None:
    command = shutil.which("apksigner") or shutil.which("apksigner.bat")
    if command:
        return Path(command).resolve()
    candidates: list[Path] = []

    def version_key(path: Path) -> tuple[int, ...]:
        numbers = re.findall(r"\d+", path.name)
        return tuple(int(value) for value in numbers)

    for root in _sdk_roots(apkanalyzer):
        build_tools = root / "build-tools"
        if not build_tools.is_dir():
            continue
        for version_dir in sorted(build_tools.iterdir(), key=version_key, reverse=True):
            candidates.extend([version_dir / "apksigner.bat", version_dir / "apksigner"])
    return _first_existing(candidates)


def run_tool(tool: Path, args: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    """Run a trusted SDK tool without a shell except where Windows batch requires it."""

    if os.name == "nt" and tool.suffix.lower() in {".bat", ".cmd"}:
        command_line = subprocess.list2cmdline([str(tool), *args])
        command = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", command_line]
    else:
        command = [str(tool), *args]
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        creationflags=_subprocess_creation_flags(),
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        shell=False,
    )
