"""Finish a manual capture session without requiring an Agent1 conversation."""

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
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from PIL import Image, ImageStat, UnidentifiedImageError

from apkba_analyzer.device import (
    PENDING_FILE_NAME,
    RECORDING_DIRECTORY,
    SCREENSHOT_DIRECTORY,
    AdbClient,
    device_session_lock,
    record_media_capture_end,
)
from apkba_analyzer.models import ScanFailure
from apkba_analyzer.scanner import _hash_file
from apkba_analyzer.tools import _subprocess_creation_flags

VISIBILITY_VALUES = {
    "visible",
    "protected_black_screen",
    "partially_visible_protected_content",
}
REVIEW_METHODS = {
    "representative_frame_visual_review",
    "operator_confirmed_playback",
    "representative_frame_and_operator_report",
}
FORBIDDEN_NAMES = {"logs", "issues", "unclassified_media", "manifest.json"}


def _iso_now() -> str:
    return datetime.now(UTC).astimezone().isoformat()


def _load_pending(bundle: Path) -> tuple[Path, dict[str, Any]]:
    bundle = bundle.expanduser().resolve()
    pending_path = bundle / PENDING_FILE_NAME
    if not pending_path.is_file():
        raise ScanFailure(f"该交接包没有等待完成的取证会话：{pending_path}")
    try:
        session = json.loads(pending_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ScanFailure("无法读取取证会话记录。") from error
    if not isinstance(session, dict) or session.get("status") != "awaiting_manual_capture":
        raise ScanFailure("取证会话状态无效，不能生成证据包。")
    return pending_path, session


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _session_path(bundle: Path, value: Any, fallback: str) -> Path:
    raw = str(value or fallback)
    path = Path(raw)
    return path.resolve() if path.is_absolute() else (bundle / path).resolve()


def _portable_name(value: str, fallback: str) -> str:
    value = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value)
    value = re.sub(r"\s+", "_", value).strip(" ._")
    return value[:90] or fallback


def _is_direct_child(path: Path, parent: Path) -> bool:
    try:
        return path.resolve().parent == parent.resolve()
    except OSError:
        return False


def _is_attributable(record: dict[str, Any], session: dict[str, Any]) -> bool:
    stem = PurePosixPath(str(record.get("remote_path") or "")).stem.casefold()
    label = str((session.get("app") or {}).get("application_label") or "").casefold()
    launch_result = str((session.get("launch") or {}).get("result") or "")
    if label and label in stem:
        return True
    if "settings" in stem or "permission controller" in stem:
        return True
    return launch_result == "blocked_google_play_required" and "google play store" in stem


def _bounded_media(session: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    baseline = session.get("media_baseline") or {}
    capture_end = session.get("media_capture_end") or {}
    try:
        baseline_epoch = float(baseline["device_epoch_seconds"])
        end_epoch = float(capture_end["device_epoch_seconds"])
    except (KeyError, TypeError, ValueError) as error:
        raise ScanFailure("取证基线或结束边界时间无效。") from error
    if end_epoch < baseline_epoch:
        raise ScanFailure("取证结束边界早于媒体基线。")

    def bounded(records: Any) -> list[dict[str, Any]]:
        result = []
        for record in records if isinstance(records, list) else []:
            try:
                modified = float(record["modified_epoch_seconds"])
            except (KeyError, TypeError, ValueError):
                continue
            if baseline_epoch < modified <= end_epoch:
                result.append(dict(record))
        return sorted(result, key=lambda item: float(item["modified_epoch_seconds"]))

    return bounded(capture_end.get("screenshots")), bounded(capture_end.get("recordings"))


def finish_preflight(
    bundle: str | os.PathLike[str],
    *,
    adb: AdbClient | None = None,
    record_end_if_missing: bool = True,
) -> dict[str, Any]:
    """Freeze the capture boundary if needed and return all bounded candidates."""

    bundle_path = Path(bundle).expanduser().resolve()
    _pending_path, session = _load_pending(bundle_path)
    serial = str((session.get("device") or {}).get("serial") or "")
    if not serial:
        raise ScanFailure("取证会话没有绑定手机。")
    if not session.get("media_capture_end"):
        if not record_end_if_missing:
            raise ScanFailure("尚未记录截图/录屏结束边界。")
        record_media_capture_end(bundle_path, serial, adb=adb)
        _pending_path, session = _load_pending(bundle_path)

    screenshots, recordings = _bounded_media(session)
    for record in screenshots:
        record["suggested"] = _is_attributable(record, session)
        record["file_name"] = PurePosixPath(str(record["remote_path"])).name
    for record in recordings:
        record["file_name"] = PurePosixPath(str(record["remote_path"])).name
    return {
        "status": "review_required",
        "bundlePath": str(bundle_path),
        "deviceSerial": serial,
        "deviceModel": (session.get("device") or {}).get("model"),
        "applicationLabel": (session.get("app") or {}).get("application_label"),
        "applicationLabelSource": (session.get("app") or {}).get(
            "application_label_source"
        ),
        "packageName": (session.get("app") or {}).get("package_name"),
        "screenshots": screenshots,
        "recordings": recordings,
        "suggestedScreenshotPaths": [
            record["remote_path"] for record in screenshots if record["suggested"]
        ],
        "captureEnd": session.get("media_capture_end"),
    }


def _safe_review_root(identity: str) -> Path:
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
    parent = Path(tempfile.gettempdir()) / "apkba-analyzer-review"
    parent.mkdir(parents=True, exist_ok=True)
    root = (parent / digest).resolve()
    if root.parent != parent.resolve():
        raise ScanFailure("拒绝使用不安全的媒体审查目录。")
    if root.exists():
        shutil.rmtree(root)
    root.mkdir()
    return root


def _pull(
    client: AdbClient,
    serial: str,
    remote_path: str,
    destination: Path,
    expected_root: str,
) -> None:
    prefix = expected_root.rstrip("/") + "/"
    if not remote_path.startswith(prefix):
        raise ScanFailure(f"拒绝拉取目标媒体目录之外的文件：{remote_path}")
    result = client.invoke(
        ["pull", remote_path, str(destination)],
        serial=serial,
        allow_failure=True,
        timeout=300,
    )
    if result.returncode or not destination.is_file() or destination.stat().st_size <= 0:
        detail = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        raise ScanFailure(f"无法从手机读取媒体：{PurePosixPath(remote_path).name}\n{detail}")


def _asset_path(name: str) -> Path | None:
    roots = []
    bundled = getattr(sys, "_MEIPASS", None)
    if bundled:
        roots.append(Path(bundled) / "assets")
    roots.append(Path(__file__).resolve().parent / "assets")
    for root in roots:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def _ffmpeg_frames(video: Path, output: Path) -> list[Path]:
    ffmpeg = shutil.which("ffmpeg")
    ffprobe = shutil.which("ffprobe")
    if not ffmpeg or not ffprobe:
        return []
    probe = subprocess.run(
        [
            ffprobe,
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "default=noprint_wrappers=1:nokey=1",
            str(video),
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=_subprocess_creation_flags(),
    )
    try:
        duration = float(probe.stdout.strip())
    except ValueError:
        return []
    if probe.returncode or duration <= 0:
        return []
    frames: list[Path] = []
    for index, fraction in enumerate((0.2, 0.5, 0.8), start=1):
        destination = output / f"frame_{index}.png"
        result = subprocess.run(
            [
                ffmpeg,
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-ss",
                f"{duration * fraction:.3f}",
                "-i",
                str(video),
                "-frames:v",
                "1",
                "-vf",
                "scale=720:-2",
                str(destination),
            ],
            check=False,
            capture_output=True,
            creationflags=_subprocess_creation_flags(),
        )
        if result.returncode or not destination.is_file():
            return []
        frames.append(destination)
    return frames


def _platform_thumbnail(video: Path, output: Path) -> list[Path]:
    if os.name == "nt":
        script = _asset_path("windows-video-thumbnail.ps1")
        powershell = shutil.which("powershell.exe") or shutil.which("powershell")
        if not script or not powershell:
            return []
        destination = output / "representative.png"
        result = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
                "-VideoPath",
                str(video),
                "-OutputPath",
                str(destination),
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=_subprocess_creation_flags(),
            timeout=60,
        )
        return [destination] if result.returncode == 0 and destination.is_file() else []
    qlmanage = shutil.which("qlmanage")
    if not qlmanage:
        return []
    result = subprocess.run(
        [qlmanage, "-t", "-s", "720", "-o", str(output), str(video)],
        check=False,
        capture_output=True,
        creationflags=_subprocess_creation_flags(),
        timeout=60,
    )
    if result.returncode:
        return []
    generated = sorted(
        (path for path in output.glob("*.png") if path.name != "representative.png"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not generated:
        return []
    destination = output / "representative.png"
    generated[0].replace(destination)
    return [destination]


def _visibility_suggestion(frames: list[Path]) -> tuple[str | None, list[dict[str, Any]]]:
    metrics: list[dict[str, Any]] = []
    for frame in frames:
        try:
            with Image.open(frame) as image:
                gray = image.convert("L")
                gray.thumbnail((160, 160))
                histogram = gray.histogram()
        except (OSError, UnidentifiedImageError):
            continue
        pixel_count = sum(histogram)
        if not pixel_count:
            continue
        non_dark_ratio = sum(histogram[25:]) / pixel_count
        deviation = float(ImageStat.Stat(gray).stddev[0])
        metrics.append(
            {
                "fileName": frame.name,
                "nonDarkRatio": round(non_dark_ratio, 4),
                "luminanceStdDev": round(deviation, 2),
            }
        )
    if not metrics:
        return None, metrics
    protected = all(
        item["nonDarkRatio"] < 0.06 and item["luminanceStdDev"] < 32 for item in metrics
    )
    return ("protected_black_screen" if protected else "visible"), metrics


def prepare_media_review(
    bundle: str | os.PathLike[str],
    recording_remote_path: str,
    *,
    adb: AdbClient | None = None,
) -> dict[str, Any]:
    """Pull bounded candidates into managed temp storage and create recording frames."""

    preflight = finish_preflight(bundle, adb=adb, record_end_if_missing=False)
    screenshot_records = list(preflight["screenshots"])
    recording_records = {
        str(record["remote_path"]): record for record in preflight["recordings"]
    }
    if recording_remote_path not in recording_records:
        raise ScanFailure("选择的录屏不属于本次取证边界。")
    bundle_path = Path(preflight["bundlePath"])
    serial = str(preflight["deviceSerial"])
    capture_epoch = str((preflight.get("captureEnd") or {}).get("device_epoch_seconds"))
    review_root = _safe_review_root(f"{bundle_path}|{capture_epoch}")
    screenshots_root = review_root / "screenshots"
    frames_root = review_root / "frames"
    screenshots_root.mkdir()
    frames_root.mkdir()
    client = adb or AdbClient()
    pulled_screenshots: list[dict[str, Any]] = []
    with device_session_lock(serial):
        client.device_facts(serial)
        for index, record in enumerate(screenshot_records, start=1):
            suffix = PurePosixPath(str(record["remote_path"])).suffix or ".png"
            local = screenshots_root / f"{index:03d}{suffix.lower()}"
            _pull(
                client,
                serial,
                str(record["remote_path"]),
                local,
                SCREENSHOT_DIRECTORY,
            )
            try:
                with Image.open(local) as image:
                    image.verify()
            except (OSError, UnidentifiedImageError) as error:
                raise ScanFailure(f"截图无法解码：{record['file_name']}") from error
            pulled_screenshots.append({**record, "localPath": str(local)})
        local_video = review_root / "recording.mp4"
        _pull(
            client,
            serial,
            recording_remote_path,
            local_video,
            RECORDING_DIRECTORY,
        )
    frames = _ffmpeg_frames(local_video, frames_root)
    audit_method = "ffmpeg_three_frames"
    if not frames:
        frames = _platform_thumbnail(local_video, frames_root)
        audit_method = "platform_thumbnail" if frames else "operator_playback_required"
    suggestion, metrics = _visibility_suggestion(frames)
    return {
        **preflight,
        "reviewRoot": str(review_root),
        "screenshots": pulled_screenshots,
        "selectedRecording": recording_records[recording_remote_path],
        "localRecordingPath": str(local_video),
        "recordingFrames": [str(path) for path in frames],
        "recordingAuditMethod": audit_method,
        "visibilitySuggestion": suggestion,
        "visibilityMetrics": metrics,
    }


def cleanup_media_review(review_root: str | os.PathLike[str]) -> None:
    root = Path(review_root).resolve()
    parent = (Path(tempfile.gettempdir()) / "apkba-analyzer-review").resolve()
    if root.parent != parent:
        raise ScanFailure("拒绝删除托管审查目录之外的文件。")
    if root.exists():
        shutil.rmtree(root)


def _validate_mp4(path: Path) -> None:
    if not path.is_file() or path.stat().st_size < 1024:
        raise ScanFailure("录屏文件为空或异常过小。")
    size = path.stat().st_size
    with path.open("rb") as stream:
        head = stream.read(min(size, 1024 * 1024))
        tail = b""
        if size > 1024 * 1024:
            stream.seek(max(0, size - 1024 * 1024))
            tail = stream.read()
    payload = head + tail
    if b"ftyp" not in head[:64] or (b"moov" not in payload and b"mdat" not in payload):
        raise ScanFailure("录屏不是可确认的 MP4 文件。")


def _copy_reviewed_screenshot(
    record: dict[str, Any],
    destination: Path,
    local_by_remote: dict[str, Path],
    client: AdbClient,
    serial: str,
) -> Path:
    remote = str(record["remote_path"])
    source = local_by_remote.get(remote)
    file_name = _portable_name(PurePosixPath(remote).name, "screenshot.png")
    target = destination / file_name
    if source and source.is_file():
        shutil.copy2(source, target)
    else:
        _pull(client, serial, remote, target, SCREENSHOT_DIRECTORY)
    try:
        with Image.open(target) as image:
            image.verify()
    except (OSError, UnidentifiedImageError) as error:
        raise ScanFailure(f"截图无法解码：{file_name}") from error
    return target


def validate_evidence_package(package: Path, expected_source_hash: str) -> dict[str, Any]:
    """Validate the final folder without modifying it."""

    observations_path = package / "observations.json"
    notes_path = package / "version_update_notes.md"
    ready_marker = package / "_READY"
    try:
        observations = json.loads(observations_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ScanFailure("observations.json 无法解析。") from error
    source_root = package / "source_package"
    screenshots_root = package / "screenshots"
    videos_root = package / "videos"
    if not source_root.is_dir() or not screenshots_root.is_dir() or not videos_root.is_dir():
        raise ScanFailure("证据包缺少 source_package、screenshots 或 videos 目录。")
    icons = [path for path in package.glob("icon.*") if path.is_file()]
    sources = [path for path in source_root.iterdir() if path.is_file()]
    screenshots = [path for path in screenshots_root.iterdir() if path.is_file()]
    video = package / "videos" / "raw_install_test.mp4"
    if not notes_path.is_file() or len(icons) != 1 or len(sources) != 1:
        raise ScanFailure("证据包缺少说明、唯一图标或唯一源安装包。")
    if not ready_marker.is_file() or ready_marker.stat().st_size != 0:
        raise ScanFailure("证据包缺少 0 字节的 _READY 完成标记。")
    with Image.open(icons[0]) as icon:
        width, height = icon.size
    if icons[0].stat().st_size <= 0 or width != height:
        raise ScanFailure("证据包图标不是有效正方形图片。")
    copied_hash = _hash_file(sources[0]).upper()
    if copied_hash != expected_source_hash.upper():
        raise ScanFailure("证据包内源安装包 SHA-256 不匹配。")
    developer = observations.get("developer")
    if isinstance(developer, dict) and developer.get("name"):
        developer_path = package / str(developer.get("package_path") or "")
        expected_developer_hash = str(developer.get("sha256") or "")
        if (
            not developer_path.is_file()
            or not _is_direct_child(developer_path, package)
            or not expected_developer_hash
            or _hash_file(developer_path).upper() != expected_developer_hash.upper()
        ):
            raise ScanFailure("证据包内开发者信息文件缺失或 SHA-256 不匹配。")
    media = observations.get("media") or {}
    if int(media.get("screenshot_count") or 0) != len(screenshots):
        raise ScanFailure("截图记录数量与实际文件不一致。")
    if not screenshots:
        raise ScanFailure("证据包没有可确认截图或限制说明图片。")
    recording = media.get("recording") or {}
    if recording.get("content_visibility") not in VISIBILITY_VALUES:
        raise ScanFailure("录屏缺少有效内容可见性分类。")
    if recording.get("review_method") not in REVIEW_METHODS:
        raise ScanFailure("录屏缺少有效审查方式。")
    if recording.get("operator_reported_protected_media"):
        if recording.get("content_visibility") == "visible":
            raise ScanFailure("用户报告受保护媒体时不能分类为可见。")
        if recording.get("review_method") != "representative_frame_and_operator_report":
            raise ScanFailure("受保护媒体必须同时结合代表帧和用户报告。")
    _validate_mp4(video)
    for path in package.rglob("*"):
        if path.name in FORBIDDEN_NAMES:
            raise ScanFailure(f"证据包含有禁止残留：{path.name}")
        if path.suffix.lower() == ".apk" and path.parent != package / "source_package":
            raise ScanFailure("证据包含有 source_package 之外的 split APK。")
    return {
        "status": "pass",
        "sourceSha256": copied_hash,
        "screenshotCount": len(screenshots),
        "recordingVisibility": recording["content_visibility"],
    }


def finalize_evidence(
    bundle: str | os.PathLike[str],
    selected_screenshot_paths: list[str],
    selected_recording_path: str,
    *,
    content_visibility: str,
    review_method: str,
    operator_reported_protected_media: bool = False,
    local_restriction_image: str | os.PathLike[str] | None = None,
    output_root: str | os.PathLike[str] | None = None,
    review: dict[str, Any] | None = None,
    adb: AdbClient | None = None,
) -> dict[str, Any]:
    """Pull the confirmed media and atomically create a schema-3 evidence folder."""

    started = time.monotonic()
    bundle_path = Path(bundle).expanduser().resolve()
    pending_path, session = _load_pending(bundle_path)
    screenshot_candidates, recording_candidates = _bounded_media(session)
    screenshot_by_path = {
        str(record["remote_path"]): record for record in screenshot_candidates
    }
    recording_by_path = {
        str(record["remote_path"]): record for record in recording_candidates
    }
    selected_paths = list(dict.fromkeys(selected_screenshot_paths))
    if any(path not in screenshot_by_path for path in selected_paths):
        raise ScanFailure("选中的截图包含本次边界之外的文件。")
    if selected_recording_path not in recording_by_path:
        raise ScanFailure("选中的录屏不属于本次取证边界。")
    restriction = (
        Path(local_restriction_image).expanduser().resolve()
        if local_restriction_image
        else None
    )
    if restriction and not restriction.is_file():
        raise ScanFailure("选择的截图限制说明图片不存在。")
    if not selected_paths and not restriction:
        raise ScanFailure("请至少选择一张截图，或提供截图被禁止的说明图片。")
    if content_visibility not in VISIBILITY_VALUES:
        raise ScanFailure("录屏内容可见性分类无效。")
    if review_method not in REVIEW_METHODS:
        raise ScanFailure("录屏审查方式无效。")
    if operator_reported_protected_media:
        if content_visibility == "visible":
            raise ScanFailure("已报告黑屏/受保护内容时不能选择“可见”。")
        if review_method != "representative_frame_and_operator_report":
            raise ScanFailure("受保护媒体必须结合代表帧与用户报告进行审查。")
        if not (review or {}).get("recordingFrames"):
            raise ScanFailure("受保护媒体缺少已审查的录屏代表帧。")
    if (
        review_method == "representative_frame_visual_review"
        and not (review or {}).get("recordingFrames")
    ):
        raise ScanFailure("选择代表帧审查方式时必须实际生成并审查代表帧。")

    serial = str((session.get("device") or {}).get("serial") or "")
    if not serial:
        raise ScanFailure("取证会话没有绑定手机。")
    source = _session_path(
        bundle_path,
        (session.get("source") or {}).get("path"),
        str((session.get("source") or {}).get("file_name") or ""),
    )
    icon = _session_path(
        bundle_path,
        (session.get("icon") or {}).get("path"),
        str((session.get("icon") or {}).get("file_name") or ""),
    )
    developer_session = session.get("developer")
    developer_file = None
    if isinstance(developer_session, dict) and developer_session.get("name"):
        developer_file = _session_path(
            bundle_path,
            developer_session.get("path"),
            str(developer_session.get("file_name") or ""),
        )
        expected_developer_hash = str(developer_session.get("sha256") or "")
        if (
            not developer_file.is_file()
            or not _is_direct_child(developer_file, bundle_path)
            or not expected_developer_hash
            or _hash_file(developer_file).upper() != expected_developer_hash.upper()
        ):
            raise ScanFailure("交接包中的开发者信息文件缺失或 SHA-256 校验失败。")
    if not source.is_file() or not icon.is_file():
        raise ScanFailure("交接包中的源安装包或图标已丢失。")
    expected_hash = str((session.get("source") or {}).get("sha256") or "")
    if not expected_hash or _hash_file(source).upper() != expected_hash.upper():
        raise ScanFailure("完成前源安装包 SHA-256 校验失败。")

    today = datetime.now().strftime("%Y-%m-%d")
    app = session.get("app") or {}
    app_name = _portable_name(str(app.get("application_label") or ""), "Android_App")
    package_name = str(app.get("package_name") or "")
    folder_name = f"{app_name}_{_portable_name(package_name, 'unknown.package')}_{today}"
    final_root = (
        Path(output_root).expanduser().resolve() if output_root else bundle_path
    )
    final_package = final_root / folder_name
    if final_package.exists():
        raise ScanFailure(f"拒绝覆盖已有证据包：{final_package}")
    final_root.mkdir(parents=True, exist_ok=True)
    staging = final_root / f".{folder_name}.staging-{os.urandom(8).hex()}"
    screenshots_root = staging / "screenshots"
    videos_root = staging / "videos"
    source_root = staging / "source_package"
    screenshots_root.mkdir(parents=True)
    videos_root.mkdir()
    source_root.mkdir()
    client = adb or AdbClient()
    review_screenshots = {
        str(record["remote_path"]): Path(str(record["localPath"]))
        for record in (review or {}).get("screenshots", [])
        if record.get("remote_path") and record.get("localPath")
    }
    reviewed_video = Path(str((review or {}).get("localRecordingPath") or ""))
    media_started = time.monotonic()
    screenshot_records: list[dict[str, Any]] = []
    excluded_records = [
        {
            "remote_path": record["remote_path"],
            "modified_epoch_seconds": record["modified_epoch_seconds"],
            "reason": "operator_excluded_after_local_review",
        }
        for path, record in screenshot_by_path.items()
        if path not in selected_paths
    ]
    try:
        with device_session_lock(serial):
            client.device_facts(serial)
            for remote in selected_paths:
                record = screenshot_by_path[remote]
                copied = _copy_reviewed_screenshot(
                    record,
                    screenshots_root,
                    review_screenshots,
                    client,
                    serial,
                )
                screenshot_records.append(
                    {
                        "remote_path": remote,
                        "modified_epoch_seconds": record["modified_epoch_seconds"],
                        "size_bytes": copied.stat().st_size,
                        "sha256": _hash_file(copied).upper(),
                        "source": "device_post_baseline_capture",
                        "package_path": f"screenshots/{copied.name}",
                    }
                )
            if restriction:
                restriction_name = _portable_name(restriction.name, "screenshot_restricted.png")
                restriction_target = screenshots_root / restriction_name
                if restriction_target.exists():
                    restriction_target = screenshots_root / f"operator_{restriction_name}"
                shutil.copy2(restriction, restriction_target)
                try:
                    with Image.open(restriction_target) as image:
                        image.verify()
                except (OSError, UnidentifiedImageError) as error:
                    raise ScanFailure("截图限制说明图片无法解码。") from error
                screenshot_records.append(
                    {
                        "remote_path": None,
                        "local_file_name": restriction.name,
                        "source": "operator_provided_local",
                        "attribution": "operator_confirmed_app_screenshot_restriction",
                        "size_bytes": restriction_target.stat().st_size,
                        "sha256": _hash_file(restriction_target).upper(),
                        "package_path": f"screenshots/{restriction_target.name}",
                    }
                )
            video_target = videos_root / "raw_install_test.mp4"
            if (
                reviewed_video.is_file()
                and str((review or {}).get("selectedRecording", {}).get("remote_path") or "")
                == selected_recording_path
            ):
                shutil.copy2(reviewed_video, video_target)
            else:
                _pull(
                    client,
                    serial,
                    selected_recording_path,
                    video_target,
                    RECORDING_DIRECTORY,
                )
        _validate_mp4(video_target)
        copied_source = source_root / source.name
        copied_icon = staging / f"icon{icon.suffix.lower()}"
        shutil.copy2(source, copied_source)
        shutil.copy2(icon, copied_icon)
        copied_developer = None
        if developer_file:
            copied_developer = staging / "developer.txt"
            shutil.copy2(developer_file, copied_developer)
        media_elapsed = round((time.monotonic() - media_started) * 1000)

        record_started = time.monotonic()
        with Image.open(copied_icon) as icon_image:
            icon_width, icon_height = icon_image.size
        if icon_width != icon_height:
            raise ScanFailure("图标不是正方形。")
        source_hash = _hash_file(copied_source).upper()
        recording_record = recording_by_path[selected_recording_path]
        manual_started = str((session.get("media_baseline") or {}).get("finished_local") or "")
        try:
            manual_wait_ms = round(
                (
                    datetime.now(UTC).astimezone()
                    - datetime.fromisoformat(manual_started)
                ).total_seconds()
                * 1000
            )
        except ValueError:
            manual_wait_ms = None
        observations = {
            "schema_version": 3,
            "app": {
                "application_label": app.get("application_label"),
                "application_label_source": app.get("application_label_source"),
                "package_name": package_name,
                "version_name": app.get("version_name"),
                "version_code": app.get("version_code"),
                "min_sdk": app.get("min_sdk"),
                "target_sdk": app.get("target_sdk"),
                "launch_activity": app.get("launch_activity"),
                "declared_permissions": list(app.get("declared_permissions") or []),
                "developer_name": app.get("developer_name"),
                "developer_source": app.get("developer_source"),
            },
            "developer": (
                {
                    "name": developer_session.get("name"),
                    "source": developer_session.get("source"),
                    "sha256": _hash_file(copied_developer).upper(),
                    "package_path": copied_developer.name,
                }
                if copied_developer and isinstance(developer_session, dict)
                else None
            ),
            "source": {
                "file_name": source.name,
                "format": (session.get("source") or {}).get("format"),
                "size_bytes": source.stat().st_size,
                "sha256": expected_hash.upper(),
                "copied_source_sha256": source_hash,
                "source_note": session.get("source_note"),
                "selected_splits": list(
                    (session.get("source") or {}).get("selected_splits") or []
                ),
            },
            "install": {
                "result": (session.get("install") or {}).get("result"),
                "method": (session.get("install") or {}).get("method"),
                "installed_splits": list(
                    (session.get("install") or {}).get("installed_splits") or []
                ),
                "device_supported_abis": list(
                    (session.get("device") or {}).get("supported_abis") or []
                ),
                "low_target_sdk_bypass_used": bool(
                    (session.get("install") or {}).get("low_target_sdk_bypass_used")
                ),
                "low_target_sdk_bypass": (session.get("install") or {}).get(
                    "low_target_sdk_bypass"
                ),
                "launch_result": (session.get("launch") or {}).get("result"),
                "launch_method": (session.get("launch") or {}).get("method"),
                "launch_component": (session.get("launch") or {}).get("component"),
                "launch_primary_exit_code": (session.get("launch") or {}).get(
                    "primary_exit_code"
                ),
                "launch_final_exit_code": (session.get("launch") or {}).get(
                    "final_exit_code"
                ),
                "launch_fallback_used": (session.get("launch") or {}).get(
                    "fallback_used"
                ),
                "launch_reason": (session.get("launch") or {}).get("reason"),
                "launch_system_entry_action": (session.get("launch") or {}).get(
                    "system_entry_action"
                ),
                "launch_system_entry_foreground_confirmed": bool(
                    (session.get("launch") or {}).get(
                        "system_entry_foreground_confirmed"
                    )
                ),
                "focused_activity": (session.get("launch") or {}).get("focused_activity"),
                "visible_texts": list(
                    (session.get("launch") or {}).get("visible_texts") or []
                ),
            },
            "media_baseline": session.get("media_baseline"),
            "media_capture_end": session.get("media_capture_end"),
            "media": {
                "collection_mode": "manual",
                "screenshot_count": len(screenshot_records),
                "screenshots": screenshot_records,
                "operator_confirmed_screenshot_paths": selected_paths,
                "operator_confirmed_local_screenshot": (
                    {
                        "file_name": restriction.name,
                        "attribution": "operator_confirmed_app_screenshot_restriction",
                    }
                    if restriction
                    else None
                ),
                "historical_media_package": None,
                "excluded_post_baseline_screenshots": excluded_records,
                "recording": {
                    "status": "present",
                    "content_visibility": content_visibility,
                    "review_method": review_method,
                    "operator_reported_protected_media": (
                        operator_reported_protected_media
                    ),
                    "remote_path": selected_recording_path,
                    "historical_package_path": None,
                    "source": "device_post_baseline_capture",
                    "modified_epoch_seconds": recording_record[
                        "modified_epoch_seconds"
                    ],
                    "size_bytes": video_target.stat().st_size,
                    "sha256": _hash_file(video_target).upper(),
                    "package_path": "videos/raw_install_test.mp4",
                    "audit_method": (review or {}).get("recordingAuditMethod"),
                    "representative_frame_count": len(
                        (review or {}).get("recordingFrames") or []
                    ),
                },
            },
            "icon": {
                "file_name": copied_icon.name,
                "size_bytes": copied_icon.stat().st_size,
                "width": icon_width,
                "height": icon_height,
                "square": icon_width == icon_height,
            },
            "timings": {
                "automated_prepare": session.get("automated_prepare"),
                "setup_steps": session.get("setup"),
                "manual_capture_wait_ms": manual_wait_ms,
                "completion_batches": {
                    "media_selection_and_retrieval": {"elapsed_ms": media_elapsed}
                },
            },
            "version_update_notes_status": "not_searched_fast_manual",
        }
        record_elapsed = round((time.monotonic() - record_started) * 1000)
        observations["timings"]["completion_batches"]["record_generation"] = {
            "elapsed_ms": record_elapsed
        }
        _write_json(staging / "observations.json", observations)
        (staging / "version_update_notes.md").write_text(
            "# Version update notes\n\n"
            "Status: `not_searched_fast_manual`\n\n"
            f"The packaged source reports version `{app.get('version_name')}` "
            f"(version code `{app.get('version_code')}`). "
            "No external release-note search was requested for this manual evidence workflow.\n",
            encoding="utf-8",
        )
        (staging / "_READY").write_bytes(b"")
        validation_started = time.monotonic()
        validation = validate_evidence_package(staging, expected_hash)
        validation_elapsed = round((time.monotonic() - validation_started) * 1000)
        observations["timings"]["completion_batches"]["validation_and_cleanup"] = {
            "elapsed_ms": validation_elapsed,
            "deleted_root_inputs": [],
        }
        _write_json(staging / "observations.json", observations)
        validation = validate_evidence_package(staging, expected_hash)
        staging.replace(final_package)
        pending_path.unlink()
        return {
            "status": "success",
            "packagePath": str(final_package),
            "installStatus": (session.get("install") or {}).get("result"),
            "launchStatus": (session.get("launch") or {}).get("result"),
            "screenshotCount": len(screenshot_records),
            "recordingStatus": (
                "present_visible"
                if content_visibility == "visible"
                else f"present_{content_visibility}"
            ),
            "versionUpdateNotesStatus": "not_searched_fast_manual",
            "sourceSha256": source_hash,
            "validation": validation,
            "outputRoot": str(final_root),
            "automatedElapsedMs": round((time.monotonic() - started) * 1000),
        }
    except Exception:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        raise
