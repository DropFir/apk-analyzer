"""Offline, non-executing APK/XAPK/APKM/APKS intake scanner."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import zipfile
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from xml.etree import ElementTree

from PIL import Image, UnidentifiedImageError

from apkba_analyzer import __version__
from apkba_analyzer.models import Finding, ScanFailure
from apkba_analyzer.tools import find_apkanalyzer, find_apksigner, run_tool

Progress = Callable[[int, str], None]
ANDROID_NS = "http://schemas.android.com/apk/res/android"
PHONE_LAUNCHER_CATEGORY = "android.intent.category.LAUNCHER"
LEANBACK_LAUNCHER_CATEGORY = "android.intent.category.LEANBACK_LAUNCHER"
SUPPORTED_SOURCES = {".apk", ".xapk", ".apkm", ".apks"}
SUPPORTED_IMAGES = {".png", ".jpg", ".jpeg", ".webp", ".avif"}
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_XAPK_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_ENTRIES_WARNING = 20_000
MAX_ARCHIVE_ENTRIES_HARD = 250_000
MAX_UNCOMPRESSED_BYTES = 12 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1_000
KNOWN_ANDROID_ABIS = {
    "arm64-v8a",
    "armeabi",
    "armeabi-v7a",
    "mips",
    "mips64",
    "riscv64",
    "x86",
    "x86_64",
}


def _progress(callback: Progress | None, value: int, message: str) -> None:
    if callback:
        callback(value, message)


def _hash_file(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _hash_stream(stream: Any) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest().upper()


def _safe_member_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return (
        bool(normalized)
        and not normalized.startswith("/")
        and not re.match(r"^[A-Za-z]:", normalized)
        and ".." not in path.parts
        and "\\" not in name
    )


def _archive_audit(path: Path, deep: bool, findings: list[Finding]) -> dict[str, Any]:
    if not zipfile.is_zipfile(path):
        findings.append(Finding("error", "archive.invalid_zip", "文件不是有效的 ZIP/APK 容器。"))
        return {}

    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
            unsafe = sorted(name for name in names if not _safe_member_name(name))
            encrypted = sorted(item.filename for item in infos if item.flag_bits & 0x1)
            total_compressed = sum(item.compress_size for item in infos)
            total_uncompressed = sum(item.file_size for item in infos)
            extreme = sorted(
                item.filename
                for item in infos
                if item.file_size > 1024 * 1024
                and item.file_size / max(item.compress_size, 1) > MAX_COMPRESSION_RATIO
            )

            if len(infos) > MAX_ARCHIVE_ENTRIES_HARD:
                findings.append(
                    Finding(
                        "error",
                        "archive.too_many_entries",
                        (
                            f"压缩包条目数量异常：{len(infos):,}；"
                            f"超过安全处理上限 {MAX_ARCHIVE_ENTRIES_HARD:,}。"
                        ),
                    )
                )
            elif len(infos) > MAX_ARCHIVE_ENTRIES_WARNING:
                findings.append(
                    Finding(
                        "warning",
                        "archive.many_entries",
                        (
                            f"压缩包条目较多：{len(infos):,}；已继续检查总展开体积、"
                            "压缩比、路径和条目安全性。"
                        ),
                    )
                )
            if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                findings.append(
                    Finding(
                        "error",
                        "archive.expansion_limit",
                        f"声明的解压后体积超过限制：{total_uncompressed:,} 字节。",
                    )
                )
            if duplicates:
                findings.append(
                    Finding(
                        "error",
                        "archive.duplicate_entries",
                        "压缩包含重复路径，无法安全确定应使用哪个条目。",
                        ", ".join(duplicates[:8]),
                    )
                )
            if unsafe:
                findings.append(
                    Finding(
                        "error",
                        "archive.unsafe_paths",
                        "压缩包含不安全路径。",
                        ", ".join(unsafe[:8]),
                    )
                )
            if encrypted:
                findings.append(
                    Finding(
                        "error",
                        "archive.encrypted_entries",
                        "压缩包含加密条目，无法验证。",
                        ", ".join(encrypted[:8]),
                    )
                )
            if extreme:
                findings.append(
                    Finding(
                        "error",
                        "archive.extreme_compression",
                        "压缩包包含异常压缩比条目。",
                        ", ".join(extreme[:8]),
                    )
                )

            integrity = "not_run"
            safe_to_expand = not any(item.severity == "error" for item in findings)
            if deep and safe_to_expand:
                bad_member = archive.testzip()
                integrity = "pass" if bad_member is None else "failed"
                if bad_member:
                    findings.append(
                        Finding(
                            "error",
                            "archive.crc_failed",
                            "压缩包 CRC 完整性检查失败。",
                            bad_member,
                        )
                    )
            elif not deep:
                integrity = "skipped_quick_scan"

            return {
                "entryCount": len(infos),
                "compressedBytes": total_compressed,
                "uncompressedBytes": total_uncompressed,
                "duplicateEntries": duplicates,
                "unsafeEntries": unsafe,
                "encryptedEntries": encrypted,
                "integrity": integrity,
            }
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        findings.append(Finding("error", "archive.read_failed", f"无法读取压缩包：{error}"))
        return {}


def _native_code_record(path: Path, findings: list[Finding]) -> dict[str, Any]:
    """Inventory packaged native libraries without extracting or loading them."""

    abis: set[str] = set()
    unknown_directories: set[str] = set()
    library_count = 0
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            name = info.filename.replace("\\", "/")
            if info.is_dir() or not _safe_member_name(info.filename):
                continue
            parts = PurePosixPath(name).parts
            if len(parts) < 3 or parts[0] != "lib" or not name.lower().endswith(".so"):
                continue
            library_count += 1
            abi = parts[1].lower()
            if abi in KNOWN_ANDROID_ABIS:
                abis.add(abi)
            else:
                unknown_directories.add(parts[1])

    if unknown_directories:
        findings.append(
            Finding(
                "warning",
                "native_code.unknown_abi_directories",
                "安装包含有无法识别 CPU 架构的原生库目录；安装前无法完整确认兼容性。",
                ", ".join(sorted(unknown_directories)),
            )
        )
    return {
        "libraryCount": library_count,
        "abis": sorted(abis),
        "unknownAbiDirectories": sorted(unknown_directories),
    }


def _android_attribute(node: ElementTree.Element | None, name: str) -> str | None:
    if node is None:
        return None
    value = node.attrib.get(f"{{{ANDROID_NS}}}{name}") or node.attrib.get(f"android:{name}")
    return value or None


def _number_or_text(value: Any) -> int | str | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return str(value)


def _split_types(value: Any) -> list[str]:
    return sorted({item.strip() for item in str(value or "").split(",") if item.strip()})


def _manifest_boolean(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "0xffffffff"}


def _parse_manifest_root(root: Any) -> dict[str, Any]:
    application = root.find("application")
    uses_sdk = root.find("uses-sdk")
    required_split_types = _split_types(_android_attribute(root, "requiredSplitTypes"))
    splits_required = bool(required_split_types)
    if application is not None:
        for metadata in application.findall("meta-data"):
            if _android_attribute(metadata, "name") == "com.android.vending.splits.required":
                splits_required = splits_required or _manifest_boolean(
                    _android_attribute(metadata, "value")
                )
    permissions = sorted(
        {
            value
            for tag in ("uses-permission", "uses-permission-sdk-23")
            for node in root.findall(tag)
            if (value := _android_attribute(node, "name"))
        }
    )
    required_features = sorted(
        {
            name
            for node in root.findall("uses-feature")
            if (name := _android_attribute(node, "name"))
            and (
                (required := _android_attribute(node, "required")) is None
                or _manifest_boolean(required)
            )
        }
    )
    launcher: ElementTree.Element | None = None
    launcher_type: str | None = None
    launcher_category: str | None = None
    if application is not None:
        for desired_category in (
            PHONE_LAUNCHER_CATEGORY,
            LEANBACK_LAUNCHER_CATEGORY,
        ):
            for component_type in ("activity", "activity-alias"):
                for component in application.findall(component_type):
                    for intent_filter in component.findall("intent-filter"):
                        actions = {
                            _android_attribute(node, "name")
                            for node in intent_filter.findall("action")
                        }
                        categories = {
                            _android_attribute(node, "name")
                            for node in intent_filter.findall("category")
                        }
                        if (
                            "android.intent.action.MAIN" in actions
                            and desired_category in categories
                        ):
                            launcher = component
                            launcher_type = component_type
                            launcher_category = desired_category
                            break
                    if launcher is not None:
                        break
                if launcher is not None:
                    break
            if launcher is not None:
                break

    return {
        "applicationLabel": _android_attribute(application, "label"),
        "packageName": root.attrib.get("package") or None,
        "versionName": _android_attribute(root, "versionName"),
        "versionCode": _number_or_text(_android_attribute(root, "versionCode")),
        "minSdk": _number_or_text(_android_attribute(uses_sdk, "minSdkVersion")),
        "targetSdk": _number_or_text(_android_attribute(uses_sdk, "targetSdkVersion")),
        "permissions": permissions,
        "launcherActivity": _android_attribute(launcher, "name"),
        "launcherTargetActivity": _android_attribute(launcher, "targetActivity"),
        "launcherNodeType": launcher_type,
        "launcherCategory": launcher_category,
        "requiredFeatures": required_features,
        "splitName": root.attrib.get("split") or None,
        "requiredSplitTypes": required_split_types,
        "splitRequired": splits_required,
    }


def _parse_manifest_xml(text: str) -> dict[str, Any]:
    start = text.find("<manifest")
    if start < 0:
        raise ScanFailure("解析器输出中没有找到 Android manifest。")
    text = text[start:]
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as error:
        raise ScanFailure(f"Android manifest XML 无法解析：{error}") from error
    return _parse_manifest_root(root)


def _plain_manifest_from_archive(path: Path) -> dict[str, Any] | None:
    try:
        with zipfile.ZipFile(path) as archive:
            info = archive.getinfo("AndroidManifest.xml")
            if info.file_size > MAX_MANIFEST_BYTES:
                return None
            data = archive.read(info)
    except (KeyError, OSError, zipfile.BadZipFile):
        return None
    if not data.lstrip().startswith(b"<"):
        return None
    return _parse_manifest_xml(data.decode("utf-8-sig", errors="strict"))


def _detect_source_format(path: Path) -> str:
    """Recognize bundle containers even when the downloaded extension is wrong."""

    declared = path.suffix.lower().lstrip(".")
    if path.suffix.lower() not in SUPPORTED_SOURCES:
        return declared
    try:
        with zipfile.ZipFile(path) as archive:
            all_names = {
                name
                for name in archive.namelist()
                if not name.endswith("/")
            }
            root_names = {
                name
                for name in all_names
                if len(PurePosixPath(name).parts) == 1 and not name.endswith("/")
            }
    except (OSError, zipfile.BadZipFile):
        return declared
    root_apks = {name for name in root_names if name.lower().endswith(".apk")}
    all_apks = {name for name in all_names if name.lower().endswith(".apk")}
    root_names_lower = {name.lower() for name in root_names}
    if (
        "toc.pb" in root_names_lower
        or "meta.sai_v1.json" in root_names_lower
        or "meta.sai_v2.json" in root_names_lower
    ) and all_apks:
        return "apks"
    if "manifest.json" in root_names_lower and root_apks:
        return "xapk"
    if "info.json" in root_names_lower and "base.apk" in root_names_lower:
        return "apkm"
    return declared


def _manifest_with_apkanalyzer(path: Path, tool: Path) -> dict[str, Any]:
    result = run_tool(tool, ["manifest", "print", str(path)])
    if result.returncode != 0 or not result.stdout.strip():
        detail = (result.stderr or result.stdout).strip().splitlines()
        message = detail[-1] if detail else f"exit {result.returncode}"
        raise ScanFailure(f"apkanalyzer 解析失败：{message}")
    return _parse_manifest_xml(result.stdout)


def _manifest_with_androguard(path: Path) -> dict[str, Any]:
    try:
        from androguard.core.apk import APK
        from loguru import logger
    except ImportError as error:
        raise ScanFailure("Androguard 未安装。") from error
    try:
        logger.disable("androguard")
        apk = APK(str(path))
        manifest = _parse_manifest_root(apk.get_android_manifest_xml())
        manifest.update(
            {
                "applicationLabel": apk.get_app_name() or None,
                "packageName": apk.get_package() or None,
                "versionName": apk.get_androidversion_name() or None,
                "versionCode": _number_or_text(apk.get_androidversion_code()),
                "minSdk": _number_or_text(apk.get_min_sdk_version()),
                "targetSdk": _number_or_text(apk.get_target_sdk_version()),
                "permissions": sorted(set(apk.get_permissions() or [])),
            }
        )
        return manifest
    except Exception as error:  # Androguard exposes parser-specific exception types.
        raise ScanFailure(f"Androguard 解析失败：{error}") from error


def _parse_apk_manifest(
    path: Path, apkanalyzer: Path | None, findings: list[Finding]
) -> tuple[dict[str, Any], str]:
    plain = _plain_manifest_from_archive(path)
    if plain is not None:
        return plain, "plain_xml_fixture"

    errors: list[str] = []
    try:
        return _manifest_with_androguard(path), "androguard"
    except ScanFailure as error:
        errors.append(str(error))
    if apkanalyzer:
        try:
            manifest = _manifest_with_apkanalyzer(path, apkanalyzer)
            findings.append(
                Finding(
                    "warning",
                    "manifest.androguard_fallback",
                    "内置解析器失败，已使用 Android SDK 解析器完成。",
                    errors[-1],
                )
            )
            return manifest, "apkanalyzer"
        except ScanFailure as error:
            errors.append(str(error))
    raise ScanFailure("；".join(errors) or "没有可用的 APK manifest 解析器。")


def _verify_signature_with_apksigner(path: Path, tool: Path) -> dict[str, Any]:
    result = run_tool(tool, ["verify", "--verbose", "--print-certs", str(path)])
    output = "\n".join(part for part in (result.stdout, result.stderr) if part)
    digests = sorted(
        {
            match.replace(":", "").upper()
            for match in re.findall(
                (
                    r"^\s*Signer(?:\s+#\d+|\s+\([^)\r\n]+\))"
                    r"\s+certificate SHA-256 digest:\s*([0-9a-f:]{64,95})\s*$"
                ),
                output,
                re.IGNORECASE | re.MULTILINE,
            )
            if re.fullmatch(r"[0-9A-F]{64}", match.replace(":", "").upper())
        }
    )
    verified = result.returncode == 0 and bool(digests)
    if result.returncode == 0 and not digests:
        status = "certificate_missing"
        error = "apksigner 验证通过，但输出中没有当前签名者证书 SHA-256。"
    elif result.returncode == 0:
        status = "verified"
        error = None
    else:
        status = "failed"
        error = (output.strip().splitlines()[-1:] or [None])[0]
    return {
        "status": status,
        "verified": verified,
        "certificateSha256": digests,
        "tool": "apksigner",
        "error": error,
    }


def _verify_signature_with_androguard(path: Path) -> dict[str, Any]:
    try:
        from androguard.core.apk import APK
        from loguru import logger

        logger.disable("androguard")
        apk = APK(str(path), skip_analysis=True)
        certificates: list[bytes] = []
        for method_name in (
            "get_certificates_der_v3",
            "get_certificates_der_v2",
            "get_certificates_der_v1",
        ):
            method = getattr(apk, method_name, None)
            if method:
                certificates.extend(method() or [])
        digests = sorted({hashlib.sha256(value).hexdigest().upper() for value in certificates})
        return {
            "status": "certificate_extracted" if digests else "not_verified",
            "verified": False,
            "certificateSha256": digests,
            "tool": "androguard",
            "error": None if digests else "未找到可解析的签名证书。",
        }
    except Exception as error:
        return {
            "status": "not_verified",
            "verified": False,
            "certificateSha256": [],
            "tool": "none",
            "error": str(error),
        }


def _verify_apk_signature(path: Path, apksigner: Path | None) -> dict[str, Any]:
    if apksigner:
        return _verify_signature_with_apksigner(path, apksigner)
    return _verify_signature_with_androguard(path)


def _icon_record(path: Path, findings: list[Finding]) -> dict[str, Any]:
    try:
        with Image.open(path) as image:
            image.verify()
        with Image.open(path) as image:
            width, height = image.size
            image_format = image.format
            mode = image.mode
    except (OSError, UnidentifiedImageError, ValueError) as error:
        findings.append(Finding("error", "icon.invalid", f"图标不是有效图片：{error}"))
        return {}

    if width != height:
        findings.append(
            Finding("error", "icon.not_square", f"图标必须为正方形，当前为 {width} × {height}。")
        )
    elif width < 256:
        findings.append(
            Finding(
                "warning", "icon.low_resolution", f"图标仅 {width} × {height}，建议至少 256 × 256。"
            )
        )
    return {
        "fileName": path.name,
        "sizeBytes": path.stat().st_size,
        "sha256": _hash_file(path),
        "format": image_format,
        "mode": mode,
        "width": width,
        "height": height,
        "square": width == height,
    }


def _base_split(manifest: dict[str, Any]) -> dict[str, Any] | None:
    splits = manifest.get("split_apks") or manifest.get("splitApks") or []
    for split in splits:
        if str(split.get("id", "")).lower() == "base":
            return split
    return None


def _verify_split_signatures(
    archive: zipfile.ZipFile,
    temporary_root: Path,
    split_rows: list[dict[str, Any]],
    base_file: str,
    base_path: Path,
    apksigner: Path | None,
    findings: list[Finding],
    package_label: str,
) -> dict[str, Any]:
    signature_rows: list[dict[str, Any]] = []
    for index, row in enumerate(split_rows):
        split_path = temporary_root / f"split-{index:04d}.apk"
        if row["file"] == base_file:
            split_path = base_path
        else:
            with (
                archive.open(row["file"]) as input_stream,
                split_path.open("wb") as output_stream,
            ):
                shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
        signature = _verify_apk_signature(split_path, apksigner)
        signature_rows.append(
            {
                "file": row["file"],
                "status": signature["status"],
                "verified": signature["verified"],
                "certificateSha256": signature["certificateSha256"],
            }
        )

    digest_sets = {
        tuple(row["certificateSha256"]) for row in signature_rows if row["certificateSha256"]
    }
    all_verified = bool(signature_rows) and all(row["verified"] for row in signature_rows)
    missing_certificate = any(row["status"] == "certificate_missing" for row in signature_rows)
    if len(digest_sets) > 1:
        findings.append(
            Finding(
                "error",
                "signature.split_mismatch",
                f"{package_label} split APK 的签名证书不一致。",
            )
        )
    elif missing_certificate:
        findings.append(
            Finding(
                "error",
                "signature.certificate_missing",
                f"{package_label} 至少一个 split 未能读取当前签名证书 SHA-256。",
            )
        )
    elif not all_verified:
        findings.append(
            Finding(
                "warning",
                "signature.not_fully_verified",
                "未能用 apksigner 完整验证所有 split；已保留可提取的证书信息。",
            )
        )
    return {
        "status": "verified" if all_verified and len(digest_sets) <= 1 else "not_fully_verified",
        "verified": all_verified and len(digest_sets) <= 1,
        "certificateSha256": list(next(iter(digest_sets), ())),
        "tool": "apksigner" if apksigner else "androguard",
        "splits": signature_rows,
    }


def _read_inferred_xapk(
    archive: zipfile.ZipFile,
    apkanalyzer: Path | None,
    apksigner: Path | None,
    findings: list[Finding],
    progress: Progress | None,
) -> tuple[dict[str, Any], dict[str, Any], str, dict[str, Any]]:
    """Infer a raw split archive only when its APK manifests form one provable set."""

    names = archive.namelist()
    unsafe_apks = [
        name
        for name in names
        if name.lower().endswith(".apk") and not _safe_member_name(name)
    ]
    if unsafe_apks:
        raise ScanFailure(f"XAPK 包含不安全的 APK 路径：{unsafe_apks[0]}")
    apk_names = sorted(
        {
            name
            for name in names
            if name.lower().endswith(".apk") and _safe_member_name(name)
        }
    )
    if not apk_names:
        raise ScanFailure("XAPK 缺少 manifest.json，且内部没有找到 APK。")

    with tempfile.TemporaryDirectory(prefix="apkba-xapk-inferred-") as temporary:
        temporary_root = Path(temporary)
        parsed: list[dict[str, Any]] = []
        parser_names: set[str] = set()
        _progress(progress, 48, "从内层 APK manifest 推断分包结构…")
        for index, file_name in enumerate(apk_names):
            apk_path = temporary_root / f"manifest-{index:04d}.apk"
            info = archive.getinfo(file_name)
            with (
                archive.open(info) as input_stream,
                apk_path.open("wb") as output_stream,
            ):
                shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
            manifest, parser_name = _parse_apk_manifest(
                apk_path, apkanalyzer, findings
            )
            parser_names.add(parser_name)
            with archive.open(info) as stream:
                digest = _hash_stream(stream)
            parsed.append(
                {
                    "file": file_name,
                    "path": apk_path,
                    "manifest": manifest,
                    "sizeBytes": info.file_size,
                    "sha256": digest,
                }
            )

        base_candidates = [
            item for item in parsed if not item["manifest"].get("splitName")
        ]
        if len(base_candidates) != 1:
            raise ScanFailure(
                "XAPK 缺少 manifest.json，且无法从内层 manifest 唯一确认 base APK。"
            )
        base = base_candidates[0]
        base_manifest = base["manifest"]
        base_package = str(base_manifest.get("packageName") or "")
        base_version = base_manifest.get("versionCode")
        if not base_package or base_version is None:
            raise ScanFailure(
                "XAPK 缺少 manifest.json，且 base APK 未提供可核对的包名或版本号。"
            )

        split_ids: set[str] = set()
        split_rows: list[dict[str, Any]] = []
        for item in parsed:
            manifest = item["manifest"]
            package_name = str(manifest.get("packageName") or "")
            version_code = manifest.get("versionCode")
            if package_name != base_package:
                raise ScanFailure(
                    "XAPK 缺少 manifest.json，且内层 APK 包名不一致："
                    f"{item['file']}={package_name or 'missing'}；base={base_package}。"
                )
            if version_code is None or str(version_code) != str(base_version):
                raise ScanFailure(
                    "XAPK 缺少 manifest.json，且内层 APK 版本号不一致："
                    f"{item['file']}={version_code!s}；base={base_version!s}。"
                )
            split_id = (
                "base"
                if item is base
                else str(manifest.get("splitName") or "").strip()
            )
            if not split_id:
                raise ScanFailure(
                    f"XAPK 无法确认内层分包名称：{item['file']}"
                )
            if split_id in split_ids:
                raise ScanFailure(
                    f"XAPK 内层 manifest 存在重复分包名称：{split_id}"
                )
            split_ids.add(split_id)
            split_rows.append(
                {
                    "id": split_id,
                    "file": item["file"],
                    "sizeBytes": item["sizeBytes"],
                    "sha256": item["sha256"],
                }
            )

        app = dict(base_manifest)
        app["nativeCode"] = _native_code_record(base["path"], findings)
        _progress(progress, 66, "验证推断出的 XAPK split 签名…")
        signature_record = _verify_split_signatures(
            archive,
            temporary_root,
            split_rows,
            str(base["file"]),
            base["path"],
            apksigner,
            findings,
            "XAPK",
        )

    findings.append(
        Finding(
            "warning",
            "xapk.manifest_inferred",
            "XAPK 缺少 manifest.json；已根据内层 APK 的包名、版本、split 名称和签名"
            "重建分包清单。",
        )
    )
    bundle = {
        "bundleFormat": "manifest_inferred_xapk",
        "manifestInferred": True,
        "xapkVersion": None,
        "baseApk": str(base["file"]),
        "splitConfigs": [
            row["id"] for row in split_rows if str(row["id"]).startswith("config.")
        ],
        "splits": split_rows,
        "undeclaredApks": [],
        "totalSize": sum(row["sizeBytes"] for row in split_rows),
    }
    parser_name = (
        next(iter(parser_names))
        if len(parser_names) == 1
        else "+".join(sorted(parser_names))
    )
    return app, bundle, parser_name, signature_record


def _read_xapk(
    source: Path,
    apkanalyzer: Path | None,
    apksigner: Path | None,
    findings: list[Finding],
    progress: Progress | None,
) -> tuple[dict[str, Any], dict[str, Any], str, dict[str, Any]]:
    with zipfile.ZipFile(source) as archive:
        try:
            manifest_info = archive.getinfo("manifest.json")
        except KeyError:
            return _read_inferred_xapk(
                archive, apkanalyzer, apksigner, findings, progress
            )
        if manifest_info.file_size > MAX_XAPK_MANIFEST_BYTES:
            raise ScanFailure("XAPK manifest.json 异常过大。")
        try:
            xapk_manifest = json.loads(archive.read(manifest_info).decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ScanFailure(f"XAPK manifest.json 无法解析：{error}") from error
        base = _base_split(xapk_manifest)
        if not base or not base.get("file"):
            raise ScanFailure("XAPK manifest.json 没有声明 base APK。")

        split_rows: list[dict[str, Any]] = []
        declared = xapk_manifest.get("split_apks") or xapk_manifest.get("splitApks") or []
        if not isinstance(declared, list) or not declared:
            raise ScanFailure("XAPK manifest.json 没有有效的 split_apks 清单。")
        names = set(archive.namelist())
        for split in declared:
            file_name = str(split.get("file", ""))
            if (
                not file_name
                or not _safe_member_name(file_name)
                or not file_name.lower().endswith(".apk")
            ):
                findings.append(
                    Finding(
                        "error",
                        "xapk.invalid_split_path",
                        "XAPK 声明了无效 split 路径。",
                        file_name,
                    )
                )
                continue
            if file_name not in names:
                findings.append(
                    Finding(
                        "error", "xapk.missing_split", "XAPK 缺少已声明的 split APK。", file_name
                    )
                )
                continue
            info = archive.getinfo(file_name)
            with archive.open(info) as stream:
                digest = _hash_stream(stream)
            split_rows.append(
                {
                    "id": str(split.get("id", "")),
                    "file": file_name,
                    "sizeBytes": info.file_size,
                    "sha256": digest,
                }
            )

        declared_files = {row["file"] for row in split_rows}
        undeclared_apks = sorted(
            name for name in names if name.lower().endswith(".apk") and name not in declared_files
        )
        if undeclared_apks:
            findings.append(
                Finding(
                    "warning",
                    "xapk.undeclared_apks",
                    "XAPK 内含未在 split_apks 中声明的 APK。",
                    ", ".join(undeclared_apks[:8]),
                )
            )

        with tempfile.TemporaryDirectory(prefix="apkba-xapk-") as temporary:
            temporary_root = Path(temporary)
            base_file = str(base["file"])
            base_path = temporary_root / "base.apk"
            with archive.open(base_file) as source_stream, base_path.open("wb") as target_stream:
                shutil.copyfileobj(source_stream, target_stream, length=1024 * 1024)
            _progress(progress, 52, "解析 base APK manifest…")
            app, parser_name = _parse_apk_manifest(base_path, apkanalyzer, findings)
            app["nativeCode"] = _native_code_record(base_path, findings)

            _progress(progress, 66, "验证 XAPK split 签名…")
            signature_record = _verify_split_signatures(
                archive,
                temporary_root,
                split_rows,
                base_file,
                base_path,
                apksigner,
                findings,
                "XAPK",
            )

    top_package = xapk_manifest.get("package_name") or xapk_manifest.get("packageName")
    top_version_code = xapk_manifest.get("version_code") or xapk_manifest.get("versionCode")
    if top_package and app.get("packageName") and top_package != app["packageName"]:
        findings.append(
            Finding(
                "error",
                "xapk.package_mismatch",
                "XAPK package_name 与 base APK manifest 不一致。",
                f"XAPK={top_package}; base={app['packageName']}",
            )
        )
    if (
        top_version_code is not None
        and app.get("versionCode") is not None
        and str(top_version_code) != str(app["versionCode"])
    ):
        findings.append(
            Finding(
                "warning",
                "xapk.version_code_mismatch",
                "XAPK version_code 与 base APK manifest 不一致。",
                f"XAPK={top_version_code}; base={app['versionCode']}",
            )
        )

    app.update(
        {
            "applicationLabel": xapk_manifest.get("name") or app.get("applicationLabel"),
            "packageName": top_package or app.get("packageName"),
            "versionName": xapk_manifest.get("version_name")
            or xapk_manifest.get("versionName")
            or app.get("versionName"),
            "versionCode": _number_or_text(top_version_code)
            if top_version_code is not None
            else app.get("versionCode"),
            "minSdk": _number_or_text(
                xapk_manifest.get("min_sdk_version") or xapk_manifest.get("minSdkVersion")
            )
            or app.get("minSdk"),
            "targetSdk": _number_or_text(
                xapk_manifest.get("target_sdk_version") or xapk_manifest.get("targetSdkVersion")
            )
            or app.get("targetSdk"),
            "permissions": sorted(
                set(xapk_manifest.get("permissions") or app.get("permissions") or [])
            ),
        }
    )
    xapk = {
        "xapkVersion": _number_or_text(
            xapk_manifest.get("xapk_version") or xapk_manifest.get("xapkVersion")
        ),
        "baseApk": str(base["file"]),
        "splitConfigs": xapk_manifest.get("split_configs")
        or xapk_manifest.get("splitConfigs")
        or [],
        "splits": split_rows,
        "undeclaredApks": undeclared_apks,
        "totalSize": _number_or_text(
            xapk_manifest.get("total_size") or xapk_manifest.get("totalSize")
        ),
    }
    return app, xapk, parser_name, signature_record


def _apkm_split_id(file_name: str) -> str:
    name = PurePosixPath(file_name).name
    if name.lower() == "base.apk":
        return "base"
    stem = name[:-4] if name.lower().endswith(".apk") else name
    if stem.startswith("split_"):
        stem = stem[6:]
    return stem


def _apks_split_id(file_name: str, modules: set[str], base_file: str) -> str:
    """Translate bundletool APKS filenames into the generic split-id model."""

    if file_name == base_file:
        return "base"
    name = PurePosixPath(file_name).name
    stem = name[:-4] if name.lower().endswith(".apk") else name
    if stem.endswith("-master"):
        return stem[: -len("-master")]
    for module in sorted(modules, key=len, reverse=True):
        prefix = f"{module}-"
        if stem.startswith(prefix):
            qualifier = stem[len(prefix) :]
            return (
                f"config.{qualifier}"
                if module == "base"
                else f"{module}.config.{qualifier}"
            )
    raise ScanFailure(f"APKS 中无法识别分包文件名：{file_name}")


def _read_apks(
    source: Path,
    apkanalyzer: Path | None,
    apksigner: Path | None,
    findings: list[Finding],
    progress: Progress | None,
) -> tuple[dict[str, Any], dict[str, Any], str, dict[str, Any]]:
    """Read bundletool, SAI, or device-specific APKS without executing contents."""

    with zipfile.ZipFile(source) as archive:
        names = [name for name in archive.namelist() if not name.endswith("/")]
        root_names = {
            name
            for name in names
            if len(PurePosixPath(name).parts) == 1
        }
        root_names_by_lower = {name.lower(): name for name in root_names}
        toc_present = "toc.pb" in root_names_by_lower
        sai_meta_file = root_names_by_lower.get("meta.sai_v2.json") or root_names_by_lower.get(
            "meta.sai_v1.json"
        )
        container_kind = "bundletool" if toc_present else "sai" if sai_meta_file else "generic"
        if any(name.lower().startswith("asset-slices/") for name in names):
            raise ScanFailure(
                "该 bundletool APKS 含有定向 asset-slices；当前版本不能仅凭文件名"
                "安全选择纹理/资源包，请先用 bundletool 为目标手机提取设备专用 APKS。"
            )

        unsafe_apks = [
            name
            for name in names
            if name.lower().endswith(".apk") and not _safe_member_name(name)
        ]
        if unsafe_apks:
            raise ScanFailure(f"APKS 包含不安全的 APK 路径：{unsafe_apks[0]}")
        apk_names = sorted(
            {
                name
                for name in names
                if name.lower().endswith(".apk") and _safe_member_name(name)
            }
        )
        if not apk_names:
            raise ScanFailure("APKS 中没有找到 APK。")

        universal_candidates = [
            name
            for name in apk_names
            if PurePosixPath(name).name.lower() == "universal.apk"
        ]
        if len(universal_candidates) > 1:
            raise ScanFailure("APKS 包含多个 universal.apk，无法安全判断安装目标。")

        if universal_candidates:
            base_file = universal_candidates[0]
            selected_names = [base_file]
            mode = "universal"
        else:
            base_candidates = [
                name
                for name in apk_names
                if PurePosixPath(name).name.lower() in {"base-master.apk", "base.apk"}
            ]
            if len(base_candidates) == 1:
                base_file = base_candidates[0]
                family = PurePosixPath(base_file).parent
                selected_names = [
                    name for name in apk_names if PurePosixPath(name).parent == family
                ]
                mode = "split"
            elif not base_candidates and len(apk_names) == 1:
                base_file = apk_names[0]
                selected_names = [base_file]
                mode = "standalone"
            elif not base_candidates:
                raise ScanFailure(
                    "APKS 仅包含多个 standalone 设备变体，无法离线安全选择；"
                    "请提供 universal APK 或仅包含目标设备变体的 APKS。"
                )
            else:
                raise ScanFailure("APKS 包含多个 base APK，无法安全判断分包集合。")

        modules: set[str] = set()
        if container_kind == "bundletool":
            modules = {
                PurePosixPath(name).name[: -len("-master.apk")]
                for name in selected_names
                if PurePosixPath(name).name.lower().endswith("-master.apk")
            }
            modules.add("base")
        split_rows: list[dict[str, Any]] = []
        for file_name in selected_names:
            info = archive.getinfo(file_name)
            with archive.open(info) as stream:
                digest = _hash_stream(stream)
            split_id = (
                _apks_split_id(file_name, modules, base_file)
                if container_kind == "bundletool"
                else (
                    "base"
                    if file_name == base_file
                    else _apkm_split_id(file_name)
                )
            )
            split_rows.append(
                {
                    "id": split_id,
                    "file": file_name,
                    "sizeBytes": info.file_size,
                    "sha256": digest,
                }
            )

        metadata: dict[str, Any] = {}
        if sai_meta_file:
            metadata_info = archive.getinfo(sai_meta_file)
            if metadata_info.file_size > MAX_XAPK_MANIFEST_BYTES:
                raise ScanFailure("APKS SAI 元数据异常过大。")
            try:
                parsed = json.loads(archive.read(metadata_info).decode("utf-8-sig"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ScanFailure(f"APKS SAI 元数据无法解析：{error}") from error
            if isinstance(parsed, dict):
                metadata = parsed

        with tempfile.TemporaryDirectory(prefix="apkba-apks-") as temporary:
            temporary_root = Path(temporary)
            base_path = temporary_root / "base.apk"
            with archive.open(base_file) as source_stream, base_path.open("wb") as target_stream:
                shutil.copyfileobj(source_stream, target_stream, length=1024 * 1024)
            _progress(progress, 52, "解析 APKS base APK manifest…")
            app, parser_name = _parse_apk_manifest(base_path, apkanalyzer, findings)
            app["nativeCode"] = _native_code_record(base_path, findings)
            _progress(progress, 66, "验证 APKS split 签名…")
            signature_record = _verify_split_signatures(
                archive,
                temporary_root,
                split_rows,
                base_file,
                base_path,
                apksigner,
                findings,
                "APKS",
            )

    top_package = metadata.get("package")
    top_version_code = metadata.get("version_code")
    if top_package and app.get("packageName") and top_package != app["packageName"]:
        findings.append(
            Finding(
                "error",
                "apks.package_mismatch",
                "APKS SAI 元数据包名与 base APK manifest 不一致。",
                f"APKS={top_package}; base={app['packageName']}",
            )
        )
    if (
        top_version_code is not None
        and app.get("versionCode") is not None
        and str(top_version_code) != str(app["versionCode"])
    ):
        findings.append(
            Finding(
                "warning",
                "apks.version_code_mismatch",
                "APKS SAI 元数据版本号与 base APK manifest 不一致。",
                f"APKS={top_version_code}; base={app['versionCode']}",
            )
        )
    app.update(
        {
            "applicationLabel": metadata.get("label") or app.get("applicationLabel"),
            "packageName": top_package or app.get("packageName"),
            "versionName": metadata.get("version_name") or app.get("versionName"),
            "versionCode": _number_or_text(top_version_code)
            if top_version_code is not None
            else app.get("versionCode"),
            "minSdk": _number_or_text(metadata.get("min_sdk")) or app.get("minSdk"),
            "targetSdk": _number_or_text(metadata.get("target_sdk"))
            or app.get("targetSdk"),
        }
    )
    excluded_apks = [name for name in apk_names if name not in selected_names]
    bundle = {
        "bundleFormat": "apks",
        "apksContainer": container_kind,
        "apksMode": mode,
        "tocPresent": toc_present,
        "saiMetaFile": sai_meta_file,
        "baseApk": base_file,
        "splitConfigs": [],
        "splits": split_rows,
        "undeclaredApks": excluded_apks,
        "excludedApks": excluded_apks,
        "totalSize": sum(row["sizeBytes"] for row in split_rows),
    }
    return app, bundle, parser_name, signature_record


def _read_apkm(
    source: Path,
    apkanalyzer: Path | None,
    apksigner: Path | None,
    findings: list[Finding],
    progress: Progress | None,
) -> tuple[dict[str, Any], dict[str, Any], str, dict[str, Any]]:
    with zipfile.ZipFile(source) as archive:
        names = archive.namelist()
        apk_names = sorted(name for name in names if name.lower().endswith(".apk"))
        base_candidates = [
            name for name in apk_names if PurePosixPath(name).name.lower() == "base.apk"
        ]
        if len(base_candidates) != 1:
            raise ScanFailure("APKM 必须包含且只能包含一个 base.apk。")
        base_file = base_candidates[0]
        split_rows: list[dict[str, Any]] = []
        for file_name in apk_names:
            if not _safe_member_name(file_name):
                continue
            info = archive.getinfo(file_name)
            with archive.open(info) as stream:
                digest = _hash_stream(stream)
            split_rows.append(
                {
                    "id": _apkm_split_id(file_name),
                    "file": file_name,
                    "sizeBytes": info.file_size,
                    "sha256": digest,
                }
            )

        metadata: dict[str, Any] = {}
        if "info.json" in names:
            metadata_info = archive.getinfo("info.json")
            if metadata_info.file_size > MAX_XAPK_MANIFEST_BYTES:
                raise ScanFailure("APKM info.json 异常过大。")
            try:
                parsed = json.loads(archive.read(metadata_info).decode("utf-8-sig"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ScanFailure(f"APKM info.json 无法解析：{error}") from error
            if isinstance(parsed, dict):
                metadata = parsed

        with tempfile.TemporaryDirectory(prefix="apkba-apkm-") as temporary:
            temporary_root = Path(temporary)
            base_path = temporary_root / "base.apk"
            with archive.open(base_file) as source_stream, base_path.open("wb") as target_stream:
                shutil.copyfileobj(source_stream, target_stream, length=1024 * 1024)
            _progress(progress, 52, "解析 APKM base APK manifest…")
            app, parser_name = _parse_apk_manifest(base_path, apkanalyzer, findings)
            app["nativeCode"] = _native_code_record(base_path, findings)
            _progress(progress, 66, "验证 APKM split 签名…")
            signature_record = _verify_split_signatures(
                archive,
                temporary_root,
                split_rows,
                base_file,
                base_path,
                apksigner,
                findings,
                "APKM",
            )

    top_package = metadata.get("pname") or metadata.get("package_name")
    top_version_code = metadata.get("versioncode") or metadata.get("version_code")
    if top_package and app.get("packageName") and top_package != app["packageName"]:
        findings.append(
            Finding(
                "error",
                "apkm.package_mismatch",
                "APKM 元数据包名与 base APK manifest 不一致。",
                f"APKM={top_package}; base={app['packageName']}",
            )
        )
    if (
        top_version_code is not None
        and app.get("versionCode") is not None
        and str(top_version_code) != str(app["versionCode"])
    ):
        findings.append(
            Finding(
                "warning",
                "apkm.version_code_mismatch",
                "APKM 元数据版本号与 base APK manifest 不一致。",
                f"APKM={top_version_code}; base={app['versionCode']}",
            )
        )

    app.update(
        {
            "applicationLabel": metadata.get("app_name") or app.get("applicationLabel"),
            "packageName": top_package or app.get("packageName"),
            "versionCode": _number_or_text(top_version_code)
            if top_version_code is not None
            else app.get("versionCode"),
        }
    )
    bundle = {
        "bundleFormat": "apkm",
        "apkmVersion": _number_or_text(metadata.get("apkm_version")),
        "baseApk": base_file,
        "splitConfigs": [],
        "splits": split_rows,
        "undeclaredApks": [],
        "totalSize": sum(row["sizeBytes"] for row in split_rows),
    }
    return app, bundle, parser_name, signature_record


def scan_package(
    source_path: str | os.PathLike[str],
    icon_path: str | os.PathLike[str],
    *,
    profile: str = "standard",
    progress: Progress | None = None,
) -> dict[str, Any]:
    """Scan an APK/XAPK/APKM/APKS and icon without executing or modifying either input."""

    source = Path(source_path).expanduser().resolve()
    icon = Path(icon_path).expanduser().resolve()
    findings: list[Finding] = []
    deep = profile != "quick"
    _progress(progress, 2, "检查输入文件…")

    if not source.is_file():
        raise ScanFailure(f"找不到 APK/XAPK/APKM/APKS：{source}")
    if not icon.is_file():
        raise ScanFailure(f"找不到图标：{icon}")
    if source.suffix.lower() not in SUPPORTED_SOURCES:
        raise ScanFailure("源文件必须是 .apk、.xapk、.apkm 或 .apks。")
    if icon.suffix.lower() not in SUPPORTED_IMAGES:
        raise ScanFailure("图标必须是 PNG、JPG、WebP 或 AVIF。")
    if source.name.lower().endswith((".crdownload", ".part", ".tmp")):
        raise ScanFailure("源文件仍像是未完成下载。")

    _progress(progress, 10, "计算源文件 SHA-256…")
    declared_format = source.suffix.lower().lstrip(".")
    source_record = {
        "fileName": source.name,
        "format": declared_format,
        "sizeBytes": source.stat().st_size,
        "sha256": _hash_file(source),
    }
    _progress(progress, 22, "检查压缩包结构与完整性…")
    archive_record = _archive_audit(source, deep, findings)
    source_format = _detect_source_format(source)
    if source_format != declared_format:
        source_record["format"] = source_format
        source_record["declaredFormat"] = declared_format
        findings.append(
            Finding(
                "warning",
                "source.extension_mismatch",
                f"文件扩展名是 .{declared_format}，但内容是 {source_format.upper()}；"
                f"已按 {source_format.upper()} 处理。",
                f"original={source.name}; detectedFormat={source_format}",
            )
        )
    _progress(progress, 35, "验证图标…")
    icon_record = _icon_record(icon, findings)

    apkanalyzer = find_apkanalyzer()
    apksigner = find_apksigner(apkanalyzer)
    app: dict[str, Any] = {}
    xapk: dict[str, Any] | None = None
    parser_name = "none"
    signature: dict[str, Any] = {
        "status": "not_checked",
        "verified": False,
        "certificateSha256": [],
        "tool": "none",
    }
    package_inspection_attempted = False
    archive_blocked = any(
        item.severity == "error" and item.code.startswith("archive.")
        for item in findings
    )

    if not archive_blocked:
        package_inspection_attempted = True
        try:
            if source_format == "apk":
                _progress(progress, 50, "解析 APK manifest…")
                app, parser_name = _parse_apk_manifest(source, apkanalyzer, findings)
                app["nativeCode"] = _native_code_record(source, findings)
                if app.get("splitRequired"):
                    required_split_types = list(app.get("requiredSplitTypes") or [])
                    labels = {
                        "base__abi": "CPU 架构（ABI）",
                        "base__density": "屏幕密度",
                        "base__locale": "语言",
                    }
                    required_text = "、".join(
                        labels.get(value, value) for value in required_split_types
                    )
                    message = "该 APK 是需要配套 split 的 base APK，不能单独安装。"
                    if required_text:
                        message += f" 必需分包类型：{required_text}。"
                    message += "请提供完整 XAPK/APKM/APKS。"
                    findings.append(
                        Finding(
                            "error",
                            "manifest.required_splits_missing",
                            message,
                            (
                                "requiredSplitTypes=" + ",".join(required_split_types)
                                if required_split_types
                                else "com.android.vending.splits.required=true"
                            ),
                        )
                    )
                _progress(progress, 68, "验证 APK 签名…")
                signature = _verify_apk_signature(source, apksigner)
                if signature["status"] == "failed":
                    findings.append(
                        Finding(
                            "error",
                            "signature.verify_failed",
                            "APK 签名验证失败。",
                            signature.get("error"),
                        )
                    )
                elif signature["status"] == "certificate_missing":
                    findings.append(
                        Finding(
                            "error",
                            "signature.certificate_missing",
                            "APK 未能读取当前签名证书 SHA-256。",
                            signature.get("error"),
                        )
                    )
                elif not signature["verified"]:
                    findings.append(
                        Finding(
                            "warning",
                            "signature.not_verified",
                            "未找到 apksigner，证书已尽量提取但签名未做完整验证。",
                            signature.get("error"),
                        )
                    )
            elif source_format == "xapk":
                _progress(progress, 44, "读取 XAPK manifest 与 split 清单…")
                app, xapk, parser_name, signature = _read_xapk(
                    source, apkanalyzer, apksigner, findings, progress
                )
            elif source_format == "apkm":
                _progress(progress, 44, "读取 APKM base APK 与 split 清单…")
                app, xapk, parser_name, signature = _read_apkm(
                    source, apkanalyzer, apksigner, findings, progress
                )
            elif source_format == "apks":
                _progress(progress, 44, "读取 APKS toc 与设备分包清单…")
                app, xapk, parser_name, signature = _read_apks(
                    source, apkanalyzer, apksigner, findings, progress
                )
            else:
                raise ScanFailure(f"不支持的安装包格式：{source_format}")
        except (ScanFailure, OSError, zipfile.BadZipFile) as error:
            findings.append(Finding("error", "package.parse_failed", str(error)))

    if package_inspection_attempted:
        if not app.get("packageName"):
            findings.append(Finding("error", "manifest.package_missing", "未能确认应用包名。"))
        if not app.get("versionCode"):
            findings.append(
                Finding("warning", "manifest.version_code_missing", "未能读取 versionCode。")
            )
        if app.get("launcherCategory") == LEANBACK_LAUNCHER_CATEGORY:
            findings.append(
                Finding(
                    "warning",
                    "manifest.leanback_launcher_only",
                    "该应用仅声明 Android TV（Leanback）启动入口；普通手机不兼容。",
                    f"launcherActivity={app.get('launcherActivity')}",
                )
            )
        elif not app.get("launcherActivity"):
            findings.append(
                Finding(
                    "warning",
                    "manifest.launcher_missing",
                    "未找到可确认的 LAUNCHER activity。",
                )
            )

    errors = [item.message for item in findings if item.severity == "error"]
    warnings = [item.message for item in findings if item.severity == "warning"]
    status = "blocked" if errors else "warning" if warnings else "pass"
    _progress(progress, 92, "汇总扫描报告…")
    result = {
        "schemaVersion": 1,
        "scanner": {
            "name": "APKBA Analyzer",
            "version": __version__,
            "createdAt": datetime.now(UTC).isoformat(),
            "profile": "standard" if deep else "quick",
            "offline": True,
        },
        "status": status,
        "source": source_record,
        "icon": icon_record,
        "app": app,
        "signature": signature,
        "xapk": xapk,
        "archive": archive_record,
        "tools": {
            "manifestParser": parser_name,
            "apkanalyzerAvailable": apkanalyzer is not None,
            "apksignerAvailable": apksigner is not None,
        },
        "findings": [item.to_dict() for item in findings],
        "blockers": errors,
        "warnings": warnings,
    }
    _progress(progress, 100, "扫描完成。")
    return result
