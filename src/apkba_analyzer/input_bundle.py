"""Safe import of editor input folders and wrapper ZIP archives."""

from __future__ import annotations

import os
import re
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any

from apkba_analyzer.models import ScanFailure
from apkba_analyzer.scanner import SUPPORTED_IMAGES, SUPPORTED_SOURCES

SUPPORTED_INPUT_ARCHIVES = {".zip"}
DEVELOPER_FILE_NAMES = {"developer.txt", "develop.txt"}
SOURCE_INFO_FILE_NAMES = {"source.txt", "resource.txt"}
MAX_WRAPPER_ENTRIES = 2_000
MAX_WRAPPER_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024
MAX_WRAPPER_COMPRESSION_RATIO = 1_000


@dataclass
class ImportedInputs:
    """Resolved editor inputs and the optional temporary extraction owner."""

    source: Path
    icon: Path
    developer: Path | None = None
    source_info: Path | None = None
    _temporary: TemporaryDirectory[str] | None = None

    def cleanup(self) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None


def is_input_container(path: Path) -> bool:
    return path.is_dir() or (
        path.is_file() and path.suffix.lower() in SUPPORTED_INPUT_ARCHIVES
    )


def _safe_zip_member(name: str) -> bool:
    normalized = name.replace("\\", "/")
    pure = PurePosixPath(normalized)
    return (
        bool(normalized)
        and "\\" not in name
        and not normalized.startswith("/")
        and not re.match(r"^[A-Za-z]:", normalized)
        and ".." not in pure.parts
    )


def _choose_single(
    candidates: list[Any],
    label: str,
    *,
    required: bool,
) -> Any | None:
    if len(candidates) > 1:
        names = "、".join(str(getattr(item, "filename", item)) for item in candidates[:5])
        raise ScanFailure(f"导入内容中发现多个{label}，无法自动判断：{names}")
    if not candidates:
        if required:
            raise ScanFailure(f"导入内容中没有找到{label}。")
        return None
    return candidates[0]


def _classify(records: list[Any], name_of: Any) -> dict[str, Any | None]:
    files = [(record, Path(name_of(record)).name.lower()) for record in records]
    source = _choose_single(
        [
            record
            for record, name in files
            if Path(name).suffix.lower() in SUPPORTED_SOURCES
        ],
        "APK/XAPK/APKM/APKS 安装包",
        required=True,
    )
    exact_icons = [
        record
        for record, name in files
        if Path(name).stem.lower() == "icon"
        and Path(name).suffix.lower() in SUPPORTED_IMAGES
    ]
    icon_candidates = exact_icons or [
        record
        for record, name in files
        if Path(name).suffix.lower() in SUPPORTED_IMAGES
    ]
    icon = _choose_single(icon_candidates, "应用图标", required=True)
    developer = _choose_single(
        [record for record, name in files if name in DEVELOPER_FILE_NAMES],
        "开发者信息文件",
        required=False,
    )
    source_info = _choose_single(
        [record for record, name in files if name in SOURCE_INFO_FILE_NAMES],
        "来源信息文件",
        required=False,
    )
    return {
        "source": source,
        "icon": icon,
        "developer": developer,
        "source_info": source_info,
    }


def _folder_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for current, directories, names in os.walk(root, followlinks=False):
        directories[:] = [
            name
            for name in directories
            if not (Path(current) / name).is_symlink()
        ]
        for name in names:
            path = Path(current) / name
            if path.is_file() and not path.is_symlink():
                files.append(path)
                if len(files) > MAX_WRAPPER_ENTRIES:
                    raise ScanFailure(
                        f"导入文件夹文件数量超过 {MAX_WRAPPER_ENTRIES}，已停止自动识别。"
                    )
    return files


def _import_folder(path: Path) -> ImportedInputs:
    selected = _classify(_folder_files(path), lambda item: str(item))
    return ImportedInputs(
        source=selected["source"],
        icon=selected["icon"],
        developer=selected["developer"],
        source_info=selected["source_info"],
    )


def _zip_file_infos(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    infos = [info for info in archive.infolist() if not info.is_dir()]
    if len(infos) > MAX_WRAPPER_ENTRIES:
        raise ScanFailure(
            f"导入 ZIP 文件数量超过 {MAX_WRAPPER_ENTRIES}，已停止自动识别。"
        )
    if sum(info.file_size for info in infos) > MAX_WRAPPER_UNCOMPRESSED_BYTES:
        raise ScanFailure("导入 ZIP 解压后总体积超过 4 GB，已停止自动识别。")
    for info in infos:
        unix_mode = (info.external_attr >> 16) & 0o170000
        if not _safe_zip_member(info.filename):
            raise ScanFailure(f"导入 ZIP 包含不安全路径：{info.filename}")
        if info.flag_bits & 0x1:
            raise ScanFailure(f"导入 ZIP 包含加密文件：{info.filename}")
        if unix_mode == 0o120000:
            raise ScanFailure(f"导入 ZIP 包含符号链接：{info.filename}")
        ratio = info.file_size / max(info.compress_size, 1)
        if ratio > MAX_WRAPPER_COMPRESSION_RATIO:
            raise ScanFailure(f"导入 ZIP 文件压缩比异常：{info.filename}")
    return infos


def _copy_zip_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    destination: Path,
) -> None:
    with archive.open(info) as source, destination.open("wb") as target:
        shutil.copyfileobj(source, target, length=1024 * 1024)


def _import_zip(path: Path) -> ImportedInputs:
    if not zipfile.is_zipfile(path):
        raise ScanFailure("拖入的 .zip 不是有效 ZIP 文件。")
    temporary = tempfile.TemporaryDirectory(prefix="apkba-input-")
    root = Path(temporary.name)
    try:
        with zipfile.ZipFile(path) as archive:
            selected = _classify(_zip_file_infos(archive), lambda item: item.filename)
            destinations: dict[str, Path | None] = {
                "source": root / PurePosixPath(selected["source"].filename).name,
                "icon": root
                / f"icon{Path(PurePosixPath(selected['icon'].filename).name).suffix.lower()}",
                "developer": root / "developer.txt" if selected["developer"] else None,
                "source_info": root / "source.txt" if selected["source_info"] else None,
            }
            for role, info in selected.items():
                destination = destinations[role]
                if info is not None and destination is not None:
                    _copy_zip_member(archive, info, destination)
        return ImportedInputs(
            source=destinations["source"],
            icon=destinations["icon"],
            developer=destinations["developer"],
            source_info=destinations["source_info"],
            _temporary=temporary,
        )
    except Exception:
        temporary.cleanup()
        raise


def import_input_container(path: str | os.PathLike[str]) -> ImportedInputs:
    """Resolve one folder or wrapper ZIP into the four editor input roles."""

    resolved = Path(path).expanduser().resolve()
    if resolved.is_dir():
        return _import_folder(resolved)
    if resolved.is_file() and resolved.suffix.lower() in SUPPORTED_INPUT_ARCHIVES:
        return _import_zip(resolved)
    raise ScanFailure("只支持导入文件夹或 .zip 汇总包。")
