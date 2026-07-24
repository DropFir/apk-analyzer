"""ADB-backed Agent1 preparation without automatic screenshot or recording capture."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from apkba_analyzer.intake import create_intake_bundle
from apkba_analyzer.models import ScanFailure
from apkba_analyzer.scanner import scan_package
from apkba_analyzer.tools import _subprocess_creation_flags

SCREENSHOT_DIRECTORY = "/sdcard/DCIM/Screenshots"
RECORDING_DIRECTORY = "/sdcard/DCIM/Screen recordings"
PENDING_FILE_NAME = ".apkba-pending-session.json"

RunProcess = Callable[..., subprocess.CompletedProcess[str]]
Progress = Callable[[int, str], None]


def _bundled_root() -> Path | None:
    value = getattr(sys, "_MEIPASS", None)
    return Path(value) if value else None


def find_adb() -> Path | None:
    """Find bundled Platform Tools first, then a local Android SDK installation."""

    executable = "adb.exe" if os.name == "nt" else "adb"
    candidates: list[Path] = []
    configured = os.environ.get("APKBA_ADB")
    if configured:
        candidates.append(Path(configured))
    bundled = _bundled_root()
    if bundled:
        candidates.append(bundled / "platform-tools" / executable)
    command = shutil.which(executable) or shutil.which("adb")
    if command:
        candidates.append(Path(command))
    for key in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        if os.environ.get(key):
            candidates.append(Path(os.environ[key]) / "platform-tools" / executable)
    candidates.extend(
        [
            Path.home() / "AppData" / "Local" / "Android" / "Sdk" / "platform-tools" / executable,
            Path.home() / "Library" / "Android" / "sdk" / "platform-tools" / executable,
        ]
    )
    for candidate in candidates:
        if candidate.expanduser().is_file():
            return candidate.expanduser().resolve()
    return None


def _progress(callback: Progress | None, value: int, message: str) -> None:
    if callback:
        callback(value, message)


def _output_summary(text: str, maximum: int = 500) -> str:
    summary = " | ".join(line.strip() for line in text.splitlines()[-6:] if line.strip())
    return summary if len(summary) <= maximum else summary[:maximum] + "..."


class AdbClient:
    """Small, testable ADB client that always scopes device commands by serial."""

    def __init__(self, executable: Path | None = None, runner: RunProcess = subprocess.run):
        self.executable = executable or find_adb()
        if not self.executable:
            raise ScanFailure("未找到 ADB。请使用包含 Android Platform Tools 的发布版。")
        self._runner = runner

    def invoke(
        self,
        arguments: list[str],
        *,
        serial: str | None = None,
        allow_failure: bool = False,
        timeout: int = 120,
    ) -> subprocess.CompletedProcess[str]:
        command = [str(self.executable)]
        if serial:
            command.extend(["-s", serial])
        command.extend(arguments)
        result = self._runner(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            creationflags=_subprocess_creation_flags(),
        )
        if result.returncode and not allow_failure:
            detail = _output_summary((result.stdout or "") + "\n" + (result.stderr or ""))
            raise ScanFailure(f"ADB 执行失败 ({result.returncode})：{detail}")
        return result

    def list_devices(self) -> list[dict[str, str]]:
        result = self.invoke(["devices", "-l"], timeout=30)
        devices: list[dict[str, str]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            record = {"serial": parts[0], "state": parts[1]}
            for part in parts[2:]:
                if ":" in part:
                    key, value = part.split(":", 1)
                    record[key] = value
            devices.append(record)
        return devices

    def device_facts(self, serial: str) -> dict[str, Any]:
        state = self.invoke(["get-state"], serial=serial)
        observed = [line.strip() for line in state.stdout.splitlines() if line.strip()]
        if not observed or observed[-1] != "device":
            raise ScanFailure(f"设备 {serial} 未在线或尚未授权。请查看手机上的 USB 调试弹窗。")
        result = self.invoke(["shell", "getprop"], serial=serial)
        properties: dict[str, str] = {}
        for line in result.stdout.splitlines():
            match = re.match(r"^\[([^]]+)\]: \[(.*)]$", line)
            if match:
                properties[match.group(1)] = match.group(2)
        abi_values = [
            properties.get("ro.product.cpu.abilist", ""),
            properties.get("ro.product.cpu.abi", ""),
            properties.get("ro.product.cpu.abi2", ""),
            properties.get("ro.product.cpu.abilist64", ""),
            properties.get("ro.product.cpu.abilist32", ""),
        ]
        supported_abis: list[str] = []
        for value in abi_values:
            for abi in value.split(","):
                abi = abi.strip().lower()
                if abi and abi not in supported_abis:
                    supported_abis.append(abi)
        density_text = properties.get("ro.sf.lcd_density", "")
        density = int(density_text) if density_text.isdigit() else 0
        return {
            "serial": serial,
            "state": "device",
            "model": properties.get("ro.product.model", ""),
            "android_release": properties.get("ro.build.version.release", ""),
            "abi": properties.get("ro.product.cpu.abi", ""),
            "supported_abis": supported_abis,
            "sdk": properties.get("ro.build.version.sdk", ""),
            "locale": properties.get("persist.sys.locale", ""),
            "density_dpi": density,
        }

    def focused_activity(self, serial: str) -> str | None:
        result = self.invoke(
            ["shell", "dumpsys", "activity", "activities"],
            serial=serial,
            allow_failure=True,
        )
        patterns = (
            r"mResumedActivity.*? ([A-Za-z0-9._]+/[A-Za-z0-9._$]+)",
            r"topResumedActivity=.*? ([A-Za-z0-9._]+/[A-Za-z0-9._$]+)",
        )
        for pattern in patterns:
            match = re.search(pattern, result.stdout)
            if match:
                return match.group(1)
        top = self.invoke(
            ["shell", "dumpsys", "activity", "top"],
            serial=serial,
            allow_failure=True,
        )
        match = re.search(
            r"^\s*ACTIVITY\s+([A-Za-z0-9._]+/[A-Za-z0-9._$]+)",
            top.stdout,
            re.MULTILINE,
        )
        return match.group(1) if match else None

    def visible_ui_texts(self, serial: str) -> list[str]:
        result = self.invoke(
            ["exec-out", "uiautomator", "dump", "/dev/tty"],
            serial=serial,
            allow_failure=True,
            timeout=30,
        )
        texts: list[str] = []
        for value in re.findall(r'(?:text|content-desc)="([^"]+)"', result.stdout):
            value = value.strip()
            if value and value not in texts:
                texts.append(value)
            if len(texts) >= 12:
                break
        return texts

    def media_snapshot(self, serial: str) -> dict[str, Any]:
        command = (
            "echo __DEVICE_EPOCH__; date +%s; "
            "echo __DEVICE_TIME__; date +%Y-%m-%dT%H:%M:%S%z; "
            f"echo __SCREENSHOTS__; if [ -d '{SCREENSHOT_DIRECTORY}' ]; then "
            f"find '{SCREENSHOT_DIRECTORY}' -maxdepth 1 -type f -printf '%T@|%s|%p\\n'; fi; "
            f"echo __RECORDINGS__; if [ -d '{RECORDING_DIRECTORY}' ]; then "
            f"find '{RECORDING_DIRECTORY}' -maxdepth 1 -type f -printf '%T@|%s|%p\\n'; fi"
        )
        result = self.invoke(["shell", command], serial=serial)
        sections: dict[str, list[str]] = {}
        current: str | None = None
        for line in result.stdout.splitlines():
            marker = re.match(r"^__([A-Z_]+)__$", line)
            if marker:
                current = marker.group(1)
                sections[current] = []
            elif current:
                sections[current].append(line)

        def media(section: str) -> list[dict[str, Any]]:
            records: list[dict[str, Any]] = []
            for line in sections.get(section, []):
                match = re.match(r"^([0-9]+(?:\.[0-9]+)?)\|([0-9]+)\|(.*)$", line)
                if match:
                    records.append(
                        {
                            "modified_epoch_seconds": float(match.group(1)),
                            "size_bytes": int(match.group(2)),
                            "remote_path": match.group(3),
                        }
                    )
            return sorted(records, key=lambda item: item["modified_epoch_seconds"])

        try:
            epoch = int(sections["DEVICE_EPOCH"][0].strip())
            device_time = sections["DEVICE_TIME"][0].strip()
        except (KeyError, IndexError, ValueError) as error:
            raise ScanFailure("无法读取手机时间和媒体基线。") from error
        return {
            "device_epoch": epoch,
            "device_time": device_time,
            "screenshots": media("SCREENSHOTS"),
            "recordings": media("RECORDINGS"),
        }


def select_xapk_splits(xapk: dict[str, Any], device: dict[str, Any]) -> list[str]:
    """Select base, compatible ABI/density/language, plus non-config splits."""

    rows = list(xapk.get("splits") or [])
    base = str(xapk.get("baseApk") or "")
    if not base:
        raise ScanFailure("分包未确认 base APK。")
    selected = [base]

    def config_parts(row: dict[str, Any]) -> tuple[str, str] | None:
        split_id = str(row.get("id") or "")
        if split_id.startswith("config."):
            return "base", split_id.removeprefix("config.")
        if ".config." in split_id:
            module, qualifier = split_id.rsplit(".config.", 1)
            return module, qualifier
        return None

    config_rows = [
        (row, parts[0], parts[1])
        for row in rows
        if (parts := config_parts(row)) is not None
    ]

    def grouped(
        candidates: list[tuple[dict[str, Any], str, str]],
    ) -> dict[str, list[tuple[dict[str, Any], str]]]:
        result: dict[str, list[tuple[dict[str, Any], str]]] = {}
        for row, module, qualifier in candidates:
            result.setdefault(module, []).append((row, qualifier))
        return result

    abi_qualifiers = {
        "arm64-v8a": "arm64_v8a",
        "armeabi-v7a": "armeabi_v7a",
        "armeabi": "armeabi",
        "x86_64": "x86_64",
        "x86": "x86",
    }
    available_abi = grouped(
        [item for item in config_rows if item[2] in abi_qualifiers.values()]
    )
    supported = list(device.get("supported_abis") or [device.get("abi")])
    for module, candidates in available_abi.items():
        match = next(
            (
                row
                for abi in supported
                for row, qualifier in candidates
                if qualifier == abi_qualifiers.get(str(abi).lower())
            ),
            None,
        )
        if not match:
            provided = ", ".join(qualifier for _row, qualifier in candidates)
            raise ScanFailure(
                f"手机 ABI 与分包模块 {module} 不兼容；分包提供：{provided}。"
            )
        selected.append(str(match["file"]))

    density_map = {
        "ldpi": 120,
        "mdpi": 160,
        "tvdpi": 213,
        "hdpi": 240,
        "xhdpi": 320,
        "xxhdpi": 480,
        "xxxhdpi": 640,
    }
    density_groups = grouped([item for item in config_rows if item[2] in density_map])
    target = int(device.get("density_dpi") or 420)
    for candidates in density_groups.values():
        match, _qualifier = min(
            candidates, key=lambda item: abs(density_map[item[1]] - target)
        )
        selected.append(str(match["file"]))

    def is_language(qualifier: str) -> bool:
        return bool(
            re.fullmatch(r"[a-z]{2,3}(?:-r[A-Z]{2})?", qualifier)
            or re.fullmatch(r"b\+[A-Za-z0-9+]+", qualifier)
        )

    language_groups = grouped([item for item in config_rows if is_language(item[2])])
    language = str(device.get("locale") or "").split("-", 1)[0].split("_", 1)[0].lower()
    for candidates in language_groups.values():
        match = next(
            (
                row
                for row, qualifier in candidates
                if qualifier.lower() == language
                or qualifier.lower().startswith(f"{language}-")
                or qualifier.lower().startswith(f"b+{language}+")
            ),
            None,
        ) or next(
            (row for row, qualifier in candidates if qualifier.lower() == "en"),
            None,
        )
        if match:
            selected.append(str(match["file"]))

    for row in rows:
        split_id = str(row.get("id") or "")
        if split_id == "base" or config_parts(row) is not None:
            continue
        file_name = str(row.get("file") or "")
        if file_name and file_name not in selected:
            selected.append(file_name)
    return selected


def _extract_splits(source: Path, selected: list[str], destination: Path) -> list[Path]:
    paths: list[Path] = []
    names: set[str] = set()
    with zipfile.ZipFile(source) as archive:
        archive_names = set(archive.namelist())
        for member in selected:
            pure = PurePosixPath(member)
            if member not in archive_names or pure.is_absolute() or ".." in pure.parts:
                raise ScanFailure(f"分包中缺少或包含不安全的 split：{member}")
            file_name = pure.name
            if not file_name or file_name in names:
                raise ScanFailure(f"分包 split 文件名冲突：{file_name}")
            names.add(file_name)
            target = destination / file_name
            with archive.open(member) as source_stream, target.open("wb") as target_stream:
                shutil.copyfileobj(source_stream, target_stream, length=1024 * 1024)
            paths.append(target)
    return paths


def _launch_component(package_name: str, activity: str | None) -> str | None:
    if not activity:
        return None
    activity = activity.strip()
    if "/" in activity:
        return activity
    if activity.startswith(".") or "." in activity:
        return f"{package_name}/{activity}"
    return f"{package_name}/.{activity}"


def _system_blocker(focus: str | None) -> bool:
    if not focus:
        return False
    package = focus.split("/", 1)[0]
    return package in {
        "android",
        "com.android.settings",
        "com.android.systemui",
        "com.android.vending",
        "com.android.permissioncontroller",
        "com.google.android.permissioncontroller",
        "com.android.packageinstaller",
        "com.google.android.packageinstaller",
        "com.samsung.android.packageinstaller",
    }


def _iso_now() -> str:
    return datetime.now(UTC).astimezone().isoformat()


def prepare_bundle(
    report: dict[str, Any],
    bundle: Path,
    serial: str,
    *,
    adb: AdbClient | None = None,
    progress: Progress | None = None,
) -> dict[str, Any]:
    """Install, launch, record a baseline, and write Agent1's pending marker."""

    client = adb or AdbClient()
    handoff = json.loads((bundle / "agent1_handoff.json").read_text(encoding="utf-8"))
    source = (bundle / handoff["source"]["path"]).resolve()
    icon = (bundle / handoff["icon"]["path"]).resolve()
    pending_path = bundle / PENDING_FILE_NAME
    if pending_path.exists():
        raise ScanFailure(f"该交接包已有未完成取证：{pending_path}")
    app = report.get("app") or {}
    package_name = str(app.get("packageName") or "")
    if not package_name:
        raise ScanFailure("静态扫描没有确认包名，不能安装。")

    overall_started = time.monotonic()
    setup: dict[str, Any] = {}
    _progress(progress, 70, "确认手机状态与兼容性…")
    started = _iso_now()
    device = client.device_facts(serial)
    installed = client.invoke(
        ["shell", "pm", "path", package_name],
        serial=serial,
        allow_failure=True,
    )
    was_installed = installed.returncode == 0 and "package:" in installed.stdout
    setup["device_and_installed_check"] = {
        "started_local": started,
        "finished_local": _iso_now(),
        "status": "already_installed" if was_installed else "not_installed",
    }
    selected_splits: list[str] = []
    if handoff["source"]["format"] in {"xapk", "apkm"}:
        selected_splits = select_xapk_splits(report.get("xapk") or {}, device)

    _progress(progress, 78, "安装到已选择的手机…")
    install_started = _iso_now()
    with tempfile.TemporaryDirectory(prefix="apkba-prepare-") as temporary:
        if handoff["source"]["format"] == "apk":
            install_arguments = ["install", "-r", str(source)]
            install_method = "adb install -r"
        else:
            split_paths = _extract_splits(source, selected_splits, Path(temporary))
            install_arguments = ["install-multiple", "-r", *map(str, split_paths)]
            install_method = "adb install-multiple -r"
        install = client.invoke(install_arguments, serial=serial, allow_failure=True, timeout=300)
    install_output = (install.stdout or "") + "\n" + (install.stderr or "")
    if install.returncode or not re.search(r"(?m)^Success\s*$", install_output):
        raise ScanFailure(
            "安装没有成功；工具不会自动卸载、降级或重试。"
            f"\n{_output_summary(install_output)}"
        )
    setup["install"] = {
        "started_local": install_started,
        "finished_local": _iso_now(),
        "status": "success",
    }

    _progress(progress, 86, "启动应用并检查前台页面…")
    launch_started = _iso_now()
    component = _launch_component(package_name, app.get("launcherActivity"))
    fallback_used = False
    if component:
        primary = client.invoke(
            ["shell", "am", "start", "-n", component],
            serial=serial,
            allow_failure=True,
        )
        primary_text = (primary.stdout or "") + "\n" + (primary.stderr or "")
        accepted = primary.returncode == 0 and not re.search(
            r"(?im)^\s*(Error\b|Exception\b|Security exception\b)", primary_text
        )
        launch_method = "am_start_component"
    else:
        primary = client.invoke(
            [
                "shell",
                "monkey",
                "-p",
                package_name,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ],
            serial=serial,
            allow_failure=True,
        )
        accepted = primary.returncode == 0
        launch_method = "monkey"
    final = primary
    if not accepted and component:
        fallback_used = True
        final = client.invoke(
            [
                "shell",
                "monkey",
                "-p",
                package_name,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ],
            serial=serial,
            allow_failure=True,
        )
        launch_method = "am_start_component_then_monkey"
    time.sleep(0.5)
    focused = client.focused_activity(serial)
    if focused and focused.startswith(package_name + "/"):
        launch_result, launch_reason = "success", None
    elif focused and focused.startswith("com.android.vending/"):
        launch_result, launch_reason = "blocked_google_play_required", "google_play_foreground"
    elif not focused:
        launch_result, launch_reason = "not_confirmed", "no_focused_activity"
    elif _system_blocker(focused):
        launch_result, launch_reason = "not_confirmed", "system_component_foreground"
    else:
        launch_result, launch_reason = "not_confirmed", "unrelated_app_foreground"
    visible_texts = client.visible_ui_texts(serial) if _system_blocker(focused) else []
    setup["launch"] = {
        "started_local": launch_started,
        "finished_local": _iso_now(),
        "status": launch_result,
        "method": launch_method,
        "component": component,
        "primary_exit_code": primary.returncode,
        "final_exit_code": final.returncode,
        "fallback_used": fallback_used,
        "command_summary": _output_summary((final.stdout or "") + "\n" + (final.stderr or "")),
        "focused_activity": focused,
        "reason": launch_reason,
    }

    _progress(progress, 93, "记录人工截图和录屏之前的基线…")
    baseline_started = _iso_now()
    snapshot = client.media_snapshot(serial)
    baseline_focus = client.focused_activity(serial)
    latest_screenshot = snapshot["screenshots"][-1] if snapshot["screenshots"] else None
    latest_recording = snapshot["recordings"][-1] if snapshot["recordings"] else None
    label = str(app.get("applicationLabel") or "")
    label_needs_fallback = (
        not label or label.startswith("@") or label.lower() == package_name.lower()
    )
    app_label = package_name if label_needs_fallback else label
    pending = {
        "schema_version": 2,
        "status": "awaiting_manual_capture",
        "capture_mode": "manual",
        "evidence_root": str(bundle.resolve()),
        "source_note": "User-provided package; source attribution was not independently verified.",
        "source": {
            "path": str(source),
            "file_name": source.name,
            "format": handoff["source"]["format"],
            "size_bytes": source.stat().st_size,
            "sha256": handoff["source"]["sha256"],
            "selected_splits": selected_splits,
        },
        "icon": {"path": str(icon), "file_name": icon.name},
        "app": {
            "package_name": package_name,
            "application_label": app_label,
            "application_label_source": (
                "package_name_fallback_unverified" if label_needs_fallback else "manifest"
            ),
            "version_name": app.get("versionName"),
            "version_code": app.get("versionCode"),
            "min_sdk": app.get("minSdk"),
            "target_sdk": app.get("targetSdk"),
            "launch_activity": app.get("launcherActivity"),
            "declared_permissions": list(app.get("permissions") or []),
        },
        "device": {
            "serial": serial,
            "model": device.get("model"),
            "abi": device.get("abi"),
            "supported_abis": device.get("supported_abis"),
            "sdk": device.get("sdk"),
            "locale": device.get("locale"),
        },
        "install": {
            "result": "success",
            "method": install_method,
            "was_installed": was_installed,
            "installed_splits": selected_splits,
        },
        "launch": {
            "result": launch_result,
            "method": launch_method,
            "component": component,
            "primary_exit_code": primary.returncode,
            "final_exit_code": final.returncode,
            "fallback_used": fallback_used,
            "reason": launch_reason,
            "focused_activity": focused,
            "visible_texts": visible_texts,
        },
        "setup": setup,
        "media_baseline": {
            "started_local": baseline_started,
            "finished_local": _iso_now(),
            "device_epoch_seconds": snapshot["device_epoch"],
            "device_time": snapshot["device_time"],
            "focused_activity": baseline_focus,
            "screenshot_directory": SCREENSHOT_DIRECTORY,
            "recording_directory": RECORDING_DIRECTORY,
            "latest_screenshot_before_capture": (
                PurePosixPath(latest_screenshot["remote_path"]).name
                if latest_screenshot
                else None
            ),
            "latest_recording_before_capture": (
                PurePosixPath(latest_recording["remote_path"]).name if latest_recording else None
            ),
        },
        "automated_prepare": {
            "status": "awaiting_manual_capture",
            "elapsed_ms": round((time.monotonic() - overall_started) * 1000),
        },
    }
    temporary_path = pending_path.with_suffix(".json.tmp")
    temporary_path.write_text(
        json.dumps(pending, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary_path.replace(pending_path)
    _progress(progress, 100, "准备完成，请在手机上手动截图和录屏。")
    return {
        "status": "awaiting_manual_capture",
        "bundlePath": str(bundle),
        "pendingPath": str(pending_path),
        "packageName": package_name,
        "appName": app_label,
        "deviceModel": device.get("model"),
        "launchStatus": launch_result,
        "focusedActivity": focused,
    }


def scan_create_and_prepare(
    source_path: str | os.PathLike[str],
    icon_path: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
    serial: str,
    *,
    adb: AdbClient | None = None,
    progress: Progress | None = None,
) -> tuple[dict[str, Any], Path, dict[str, Any]]:
    """Run the editor workflow once: scan, create intake, install, launch, baseline."""

    report = scan_package(
        source_path,
        icon_path,
        profile="standard",
        progress=(lambda value, message: _progress(progress, int(value * 0.62), message)),
    )
    if report["status"] == "blocked":
        raise ScanFailure("静态扫描发现阻塞项，未安装到手机。")
    _progress(progress, 63, "复制原件并生成 Agent1 交接包…")
    bundle = create_intake_bundle(report, source_path, icon_path, output_root)
    result = prepare_bundle(report, bundle, serial, adb=adb, progress=progress)
    return report, bundle, result
