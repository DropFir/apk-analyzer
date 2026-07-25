"""Independent, local-only export of images from Android shared storage."""

from __future__ import annotations

import hashlib
import re
import shutil
from collections.abc import Callable, Iterable
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from apkba_analyzer.device import AdbClient, device_session_lock
from apkba_analyzer.models import ScanFailure

SHARED_STORAGE_ROOT = PurePosixPath("/sdcard")
SHARED_STORAGE_ALIASES = (
    SHARED_STORAGE_ROOT,
    PurePosixPath("/storage/emulated/0"),
    PurePosixPath("/storage/self/primary"),
)
IMAGE_EXTENSIONS = frozenset(
    {
        ".avif",
        ".bmp",
        ".dng",
        ".gif",
        ".heic",
        ".heif",
        ".jpeg",
        ".jpg",
        ".png",
        ".tif",
        ".tiff",
        ".webp",
    }
)

Progress = Callable[[int, str], None]


def _parse_detailed_listing(output: str) -> list[dict[str, Any]]:
    fields = output.split("\0")
    if fields and not fields[-1]:
        fields.pop()
    if not fields or len(fields) % 3:
        return []
    records: list[dict[str, Any]] = []
    for index in range(0, len(fields), 3):
        modified_text, size_text, remote_path = fields[index : index + 3]
        try:
            modified = float(modified_text)
            size = int(size_text)
        except ValueError:
            return []
        records.append(
            {
                "remote_path": remote_path,
                "file_name": PurePosixPath(remote_path).name,
                "modified_epoch_seconds": modified,
                "size_bytes": size,
            }
        )
    return records


def _parse_path_listing(output: str) -> list[dict[str, Any]]:
    return [
        {
            "remote_path": line,
            "file_name": PurePosixPath(line).name,
            "modified_epoch_seconds": None,
            "size_bytes": None,
        }
        for line in output.splitlines()
        if line.startswith("/")
    ]


def _parse_media_store_listing(output: str) -> list[dict[str, Any]]:
    paths: list[str] = []
    for line in output.splitlines():
        match = re.search(r"(?:^|\s)_data=(/.*)$", line.strip())
        if match and match.group(1) not in paths:
            paths.append(match.group(1))
    return _parse_path_listing("\n".join(paths))


def _shared_relative(path: PurePosixPath) -> PurePosixPath | None:
    for root in SHARED_STORAGE_ALIASES:
        try:
            return path.relative_to(root)
        except ValueError:
            continue
    return None


def _is_shared_image(record: dict[str, Any]) -> bool:
    path = PurePosixPath(str(record.get("remote_path") or ""))
    if _shared_relative(path) is None:
        return False
    return bool(path.name) and path.suffix.casefold() in IMAGE_EXTENSIONS


def list_phone_images(
    serial: str,
    *,
    adb: AdbClient | None = None,
) -> dict[str, Any]:
    """List image metadata under Android shared storage without pulling image bytes."""

    client = adb or AdbClient()
    warning_lines: list[str] = []
    fallback_used = False
    media_store_used = False
    with device_session_lock(serial):
        device = client.device_facts(serial)
        detailed = client.invoke(
            [
                "shell",
                "find '/sdcard' -type f -printf '%T@\\0%s\\0%p\\0'",
            ],
            serial=serial,
            allow_failure=True,
            timeout=300,
        )
        detailed_warnings = [
            line.strip()
            for line in (detailed.stderr or "").splitlines()
            if line.strip()
        ]
        records = _parse_detailed_listing(detailed.stdout or "")
        if records:
            warning_lines.extend(detailed_warnings)
        if not records:
            fallback_used = True
            fallback_warnings: list[str] = []
            for root in SHARED_STORAGE_ALIASES:
                result = client.invoke(
                    ["shell", f"find '{root}' -type f -print"],
                    serial=serial,
                    allow_failure=True,
                    timeout=300,
                )
                current_warnings = [
                    line.strip()
                    for line in (result.stderr or "").splitlines()
                    if line.strip()
                ]
                fallback_warnings.extend(current_warnings)
                records = _parse_path_listing(result.stdout or "")
                if records:
                    warning_lines.extend(current_warnings)
                    break
            if not records:
                warning_lines.extend(detailed_warnings)
                warning_lines.extend(fallback_warnings)
        if not records:
            media_store_used = True
            result = client.invoke(
                [
                    "shell",
                    "content query --uri content://media/external/images/media "
                    "--projection _data",
                ],
                serial=serial,
                allow_failure=True,
                timeout=300,
            )
            warning_lines.extend(
                line.strip()
                for line in (result.stderr or "").splitlines()
                if line.strip()
            )
            records = _parse_media_store_listing(result.stdout or "")

    images = [record for record in records if _is_shared_image(record)]
    images.sort(
        key=lambda record: (
            float(record.get("modified_epoch_seconds") or 0),
            str(record["remote_path"]).casefold(),
        ),
        reverse=True,
    )
    return {
        "status": "ready",
        "device": device,
        "serial": serial,
        "sharedStorageRoot": str(SHARED_STORAGE_ROOT),
        "images": images,
        "imageCount": len(images),
        "totalKnownBytes": sum(
            int(record["size_bytes"])
            for record in images
            if record.get("size_bytes") is not None
        ),
        "fallbackListingUsed": fallback_used,
        "mediaStoreListingUsed": media_store_used,
        "warning": " | ".join(warning_lines[-3:]),
    }


def _portable_component(value: str, fallback: str) -> str:
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value)
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" .")
    if cleaned.casefold() in {
        "aux",
        "com1",
        "com2",
        "com3",
        "com4",
        "com5",
        "com6",
        "com7",
        "com8",
        "com9",
        "con",
        "lpt1",
        "lpt2",
        "lpt3",
        "lpt4",
        "lpt5",
        "lpt6",
        "lpt7",
        "lpt8",
        "lpt9",
        "nul",
        "prn",
    }:
        cleaned = f"_{cleaned}"
    return cleaned[:120] or fallback


def _safe_relative_path(remote_path: str) -> Path:
    pure = PurePosixPath(remote_path)
    relative = _shared_relative(pure)
    if relative is None:
        raise ScanFailure(f"拒绝导出共享存储之外的文件：{remote_path}")
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ScanFailure(f"手机图片路径无效：{remote_path}")
    portable = [
        _portable_component(part, f"unnamed-{index}")
        for index, part in enumerate(relative.parts, start=1)
    ]
    return Path(*portable)


def _unique_export_root(output_root: Path, serial: str) -> Path:
    safe_serial = _portable_component(serial, "phone")
    base_name = f"APKBA-phone-images_{safe_serial}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    candidate = output_root / base_name
    suffix = 2
    while candidate.exists():
        candidate = output_root / f"{base_name}_{suffix}"
        suffix += 1
    return candidate


def export_phone_images(
    serial: str,
    records: Iterable[dict[str, Any]],
    output_root: str | Path,
    *,
    adb: AdbClient | None = None,
    progress: Progress | None = None,
) -> dict[str, Any]:
    """Pull selected shared-storage images into one collision-safe local folder."""

    selected = [dict(record) for record in records]
    if not selected:
        raise ScanFailure("没有选择要下载的手机图片。")
    root = Path(output_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    known_bytes = sum(
        int(record["size_bytes"])
        for record in selected
        if record.get("size_bytes") is not None
    )
    if known_bytes and shutil.disk_usage(root).free < known_bytes:
        raise ScanFailure("电脑目标磁盘的可用空间不足以保存所选图片。")

    export_root = _unique_export_root(root, serial)
    export_root.mkdir()
    planned: list[tuple[dict[str, Any], Path]] = []
    used_targets: set[str] = set()
    for record in selected:
        remote = str(record.get("remote_path") or "")
        relative = _safe_relative_path(remote)
        target = export_root / relative
        identity = str(target.relative_to(export_root)).casefold()
        if identity in used_targets:
            digest = hashlib.sha256(remote.encode("utf-8")).hexdigest()[:8]
            target = target.with_name(f"{target.stem}_{digest}{target.suffix}")
            identity = str(target.relative_to(export_root)).casefold()
        if identity in used_targets:
            raise ScanFailure(f"无法为同名图片生成唯一的本地路径：{remote}")
        used_targets.add(identity)
        planned.append((record, target))

    client = adb or AdbClient()
    copied: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    total = len(planned)
    with device_session_lock(serial):
        client.device_facts(serial)
        for index, (record, target) in enumerate(planned, start=1):
            remote = str(record["remote_path"])
            target.parent.mkdir(parents=True, exist_ok=True)
            if progress:
                progress(
                    round((index - 1) * 100 / total),
                    f"正在下载图片 {index}/{total}：{PurePosixPath(remote).name}",
                )
            result = client.invoke(
                ["pull", remote, str(target)],
                serial=serial,
                allow_failure=True,
                timeout=300,
            )
            if result.returncode or not target.is_file():
                failures.append(
                    {
                        "remote_path": remote,
                        "error": (result.stderr or result.stdout or "ADB pull 未生成文件").strip(),
                    }
                )
                continue
            copied.append(
                {
                    "remote_path": remote,
                    "local_path": str(target),
                    "size_bytes": target.stat().st_size,
                }
            )
    if not copied:
        if not any(export_root.iterdir()):
            export_root.rmdir()
        raise ScanFailure("所选手机图片均未能下载，请检查 USB 连接和手机授权。")
    if progress:
        progress(100, f"图片下载完成：成功 {len(copied)}，失败 {len(failures)}")
    return {
        "status": "complete" if not failures else "partial",
        "serial": serial,
        "outputPath": str(export_root),
        "requestedCount": total,
        "copiedCount": len(copied),
        "failedCount": len(failures),
        "copied": copied,
        "failures": failures,
    }
