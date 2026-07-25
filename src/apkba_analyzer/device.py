"""ADB-backed Agent1 preparation without automatic screenshot or recording capture."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
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
LowTargetSdkConfirmation = Callable[[dict[str, Any]], bool]


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


@contextmanager
def device_session_lock(
    serial: str,
    *,
    lock_root: Path | None = None,
) -> Iterator[None]:
    """Reserve one device across analyzer windows and processes."""

    root = lock_root or Path(tempfile.gettempdir()) / "apkba-analyzer-device-locks"
    root.mkdir(parents=True, exist_ok=True)
    identity = hashlib.sha256(serial.encode("utf-8")).hexdigest()
    lock_path = root / f"{identity}.lock"
    handle = lock_path.open("a+b")
    handle.seek(0, os.SEEK_END)
    if handle.tell() == 0:
        handle.write(b"\0")
        handle.flush()
    handle.seek(0)

    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError) as error:
        handle.close()
        raise ScanFailure(
            f"手机 {serial} 正被另一个 APKBA 窗口使用。"
            "请为本窗口选择另一台手机，或等待另一个窗口完成。"
        ) from error

    try:
        yield
    finally:
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


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
        (row, parts[0], parts[1]) for row in rows if (parts := config_parts(row)) is not None
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
    available_abi = grouped([item for item in config_rows if item[2] in abi_qualifiers.values()])
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
            raise ScanFailure(f"手机 ABI 与分包模块 {module} 不兼容；分包提供：{provided}。")
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
        match, _qualifier = min(candidates, key=lambda item: abs(density_map[item[1]] - target))
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


def ensure_native_abi_compatible(report: dict[str, Any], device: dict[str, Any]) -> None:
    """Stop before installation when packaged native code cannot run on the device."""

    native_code = (report.get("app") or {}).get("nativeCode") or {}
    package_abis = {
        str(value).strip().lower() for value in native_code.get("abis") or [] if str(value).strip()
    }
    if not package_abis:
        return

    device_abis = {
        str(value).strip().lower()
        for value in (device.get("supported_abis") or [device.get("abi")])
        if value and str(value).strip()
    }
    package_text = "、".join(sorted(package_abis))
    if not device_abis:
        raise ScanFailure(
            "安装包含有原生库，但未能读取目标手机支持的 CPU 架构；"
            "为避免错误安装，已在写入手机前停止。\n"
            f"安装包 ABI：{package_text}"
        )
    if package_abis.isdisjoint(device_abis):
        device_text = "、".join(sorted(device_abis))
        raise ScanFailure(
            "安装包原生库与目标手机 CPU 架构不兼容，已在写入手机前停止。\n"
            f"安装包 ABI：{package_text}\n"
            f"手机 ABI：{device_text}\n"
            "请换用包含 arm64-v8a/armeabi-v7a 的版本，或改用兼容的测试设备。"
        )


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


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    temporary_path = path.with_suffix(path.suffix + ".tmp")
    temporary_path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary_path.replace(path)


def low_target_sdk_install_requirement(
    report: dict[str, Any],
    device: dict[str, Any],
) -> dict[str, Any] | None:
    """Return the platform low-target install block that requires explicit consent."""

    app = report.get("app") or {}
    try:
        target_sdk = int(app["targetSdk"])
        device_sdk = int(device["sdk"])
    except (KeyError, TypeError, ValueError):
        return None
    if device_sdk >= 35:
        minimum_target_sdk = 24
    elif device_sdk == 34:
        minimum_target_sdk = 23
    else:
        return None
    if target_sdk >= minimum_target_sdk:
        return None
    return {
        "package_name": str(app.get("packageName") or ""),
        "target_sdk": target_sdk,
        "device_sdk": device_sdk,
        "device_minimum_target_sdk": minimum_target_sdk,
        "reason": "android_low_target_sdk_install_block",
    }


def record_media_capture_end(
    bundle: Path,
    serial: str,
    *,
    adb: AdbClient | None = None,
) -> dict[str, Any]:
    """Record the upper media boundary for one prepared manual-capture session."""

    bundle = bundle.resolve()
    pending_path = bundle / PENDING_FILE_NAME
    if not pending_path.is_file():
        raise ScanFailure(f"交接包中没有等待取证的会话：{pending_path}")
    try:
        pending = json.loads(pending_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ScanFailure(f"无法读取待处理取证记录：{pending_path}") from error
    if not isinstance(pending, dict):
        raise ScanFailure("待处理取证记录格式无效。")

    device = pending.get("device")
    prepared_serial = str(device.get("serial") or "") if isinstance(device, dict) else ""
    if not prepared_serial:
        raise ScanFailure("待处理取证记录中没有手机序列号。")
    if serial != prepared_serial:
        raise ScanFailure(
            f"本次取证绑定的是手机 {prepared_serial}，不能用手机 {serial} 记录结束边界。"
        )

    baseline = pending.get("media_baseline")
    if not isinstance(baseline, dict):
        raise ScanFailure("待处理取证记录中没有截图/录屏前基线。")
    try:
        baseline_epoch = float(baseline["device_epoch_seconds"])
    except (KeyError, TypeError, ValueError) as error:
        raise ScanFailure("截图/录屏前基线时间无效。") from error

    client = adb or AdbClient()
    with device_session_lock(serial):
        facts = client.device_facts(serial)
        snapshot = client.media_snapshot(serial)
        focused = client.focused_activity(serial)

    screenshots = [
        item
        for item in snapshot["screenshots"]
        if float(item["modified_epoch_seconds"]) > baseline_epoch
    ]
    recordings = [
        item
        for item in snapshot["recordings"]
        if float(item["modified_epoch_seconds"]) > baseline_epoch
    ]
    capture_end = {
        "status": "recorded",
        "recorded_local": _iso_now(),
        "device_epoch_seconds": snapshot["device_epoch"],
        "device_time": snapshot["device_time"],
        "focused_activity": focused,
        "screenshot_count": len(screenshots),
        "recording_count": len(recordings),
        "screenshots": screenshots,
        "recordings": recordings,
    }
    pending["media_capture_end"] = capture_end
    _write_json_atomic(pending_path, pending)
    return {
        "status": "capture_end_recorded",
        "bundlePath": str(bundle),
        "pendingPath": str(pending_path),
        "deviceSerial": serial,
        "deviceModel": facts.get("model"),
        "deviceTime": snapshot["device_time"],
        "focusedActivity": focused,
        "screenshotCount": len(screenshots),
        "recordingCount": len(recordings),
    }


def prepare_bundle(
    report: dict[str, Any],
    bundle: Path,
    serial: str,
    *,
    adb: AdbClient | None = None,
    progress: Progress | None = None,
    device: dict[str, Any] | None = None,
    low_target_sdk_bypass: dict[str, Any] | None = None,
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
    device = device or client.device_facts(serial)
    ensure_native_abi_compatible(report, device)
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
    bypass_low_target_sdk = low_target_sdk_bypass is not None
    with tempfile.TemporaryDirectory(prefix="apkba-prepare-") as temporary:
        if handoff["source"]["format"] == "apk":
            install_arguments = ["install"]
            if bypass_low_target_sdk:
                install_arguments.append("--bypass-low-target-sdk-block")
            install_arguments.extend(["-r", str(source)])
            install_method = (
                "adb install --bypass-low-target-sdk-block -r"
                if bypass_low_target_sdk
                else "adb install -r"
            )
        else:
            split_paths = _extract_splits(source, selected_splits, Path(temporary))
            install_arguments = ["install-multiple"]
            if bypass_low_target_sdk:
                install_arguments.append("--bypass-low-target-sdk-block")
            install_arguments.extend(["-r", *map(str, split_paths)])
            install_method = (
                "adb install-multiple --bypass-low-target-sdk-block -r"
                if bypass_low_target_sdk
                else "adb install-multiple -r"
            )
        install = client.invoke(install_arguments, serial=serial, allow_failure=True, timeout=300)
    install_output = (install.stdout or "") + "\n" + (install.stderr or "")
    if install.returncode or not re.search(r"(?m)^Success\s*$", install_output):
        raise ScanFailure(
            f"安装没有成功；工具不会自动卸载、降级或重试。\n{_output_summary(install_output)}"
        )
    setup["install"] = {
        "started_local": install_started,
        "finished_local": _iso_now(),
        "status": "success",
        "low_target_sdk_bypass_used": bypass_low_target_sdk,
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
            "native_abis": list((app.get("nativeCode") or {}).get("abis") or []),
            "native_library_count": int(
                (app.get("nativeCode") or {}).get("libraryCount") or 0
            ),
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
            "low_target_sdk_bypass_used": bypass_low_target_sdk,
            "low_target_sdk_bypass": low_target_sdk_bypass,
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
                PurePosixPath(latest_screenshot["remote_path"]).name if latest_screenshot else None
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
    _write_json_atomic(pending_path, pending)
    _progress(progress, 100, "准备完成，请在手机上手动截图和录屏。")
    return {
        "status": "awaiting_manual_capture",
        "bundlePath": str(bundle),
        "pendingPath": str(pending_path),
        "packageName": package_name,
        "appName": app_label,
        "deviceSerial": serial,
        "deviceModel": device.get("model"),
        "launchStatus": launch_result,
        "focusedActivity": focused,
        "lowTargetSdkBypassUsed": bypass_low_target_sdk,
        "lowTargetSdkBypass": low_target_sdk_bypass,
    }


def scan_create_and_prepare(
    source_path: str | os.PathLike[str],
    icon_path: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
    serial: str,
    *,
    adb: AdbClient | None = None,
    progress: Progress | None = None,
    confirm_low_target_sdk: LowTargetSdkConfirmation | None = None,
) -> tuple[dict[str, Any], Path, dict[str, Any]]:
    """Run the editor workflow once: scan, create intake, install, launch, baseline."""

    with device_session_lock(serial):
        report = scan_package(
            source_path,
            icon_path,
            profile="standard",
            progress=(lambda value, message: _progress(progress, int(value * 0.62), message)),
        )
        if report["status"] == "blocked":
            blockers = list(report.get("blockers") or [])
            blocker_text = (
                "\n" + "\n".join(f"- {message}" for message in blockers) if blockers else ""
            )
            raise ScanFailure("静态扫描发现阻塞项，未安装到手机。" + blocker_text)
        client = adb or AdbClient()
        _progress(progress, 63, "确认手机系统与目标 SDK 兼容性…")
        device = client.device_facts(serial)
        low_target_requirement = low_target_sdk_install_requirement(report, device)
        low_target_sdk_bypass = None
        if low_target_requirement is not None:
            if confirm_low_target_sdk is None or not confirm_low_target_sdk(
                low_target_requirement
            ):
                raise ScanFailure(
                    "已取消低目标 SDK 兼容安装；安装包未安装到手机。"
                    f" APK targetSdk={low_target_requirement['target_sdk']}，"
                    f"手机要求至少 {low_target_requirement['device_minimum_target_sdk']}。"
                )
            low_target_sdk_bypass = {
                **low_target_requirement,
                "authorization": "explicit_operator_confirmation",
            }
        _progress(progress, 63, "复制原件并生成 Agent1 交接包…")
        bundle = create_intake_bundle(report, source_path, icon_path, output_root)
        result = prepare_bundle(
            report,
            bundle,
            serial,
            adb=client,
            progress=progress,
            device=device,
            low_target_sdk_bypass=low_target_sdk_bypass,
        )
        return report, bundle, result
