"""Atomic creation of portable Agent1 intake folders."""

from __future__ import annotations

import html
import json
import os
import re
import shutil
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from apkba_analyzer.models import ScanFailure
from apkba_analyzer.scanner import _hash_file

SUPPORTED_DEVELOPER_FILES = {".txt"}
SUPPORTED_SOURCE_INFO_FILES = {".txt"}
MAX_DEVELOPER_FILE_BYTES = 16 * 1024
MAX_DEVELOPER_NAME_LENGTH = 200
MAX_SOURCE_INFO_FILE_BYTES = 64 * 1024
MAX_SOURCE_INFO_LENGTH = 4_000
PUBLISH_RETRY_DELAYS = (0.05, 0.10, 0.25, 0.50, 1.00, 2.00)
TRANSIENT_PUBLISH_WINERRORS = {5, 32, 33}


def _portable_name(value: str, fallback: str) -> str:
    value = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value).strip(" ._")
    value = re.sub(r"\s+", "_", value)
    return value[:80] or fallback


def _unique_destination(root: Path, base_name: str) -> Path:
    candidate = root / base_name
    if not candidate.exists():
        return candidate
    timestamp = datetime.now().strftime("%H%M%S")
    for index in range(1000):
        suffix = f"_{timestamp}" if index == 0 else f"_{timestamp}_{index}"
        candidate = root / f"{base_name}{suffix}"
        if not candidate.exists():
            return candidate
    raise ScanFailure("无法为交接包分配唯一目录名。")


def _publish_staging_directory(
    staging: Path,
    root: Path,
    base_name: str,
    destination: Path,
) -> Path:
    """Publish a completed staging folder despite brief Windows directory locks."""

    for attempt in range(len(PUBLISH_RETRY_DELAYS) + 1):
        try:
            staging.replace(destination)
            return destination
        except OSError as error:
            if destination.exists():
                destination = _unique_destination(root, base_name)
                continue
            transient = isinstance(error, PermissionError) or (
                getattr(error, "winerror", None) in TRANSIENT_PUBLISH_WINERRORS
            )
            if not transient:
                raise
            if attempt == len(PUBLISH_RETRY_DELAYS):
                raise ScanFailure(
                    "系统暂时无法完成交接包目录创建；输出目录可能正被资源管理器、"
                    "杀毒/同步工具或另一个程序占用。请稍后重试，或改用本地普通文件夹。"
                ) from error
            time.sleep(PUBLISH_RETRY_DELAYS[attempt])

    raise AssertionError("unreachable")


def _read_developer_name(path: Path) -> str:
    if path.suffix.lower() not in SUPPORTED_DEVELOPER_FILES:
        raise ScanFailure("开发者信息必须是 .txt 文件。")
    size = path.stat().st_size
    if size <= 0 or size > MAX_DEVELOPER_FILE_BYTES:
        raise ScanFailure("开发者信息文件必须为非空且不超过 16 KB。")
    try:
        value = " ".join(path.read_text(encoding="utf-8-sig").split())
    except UnicodeDecodeError as error:
        raise ScanFailure("开发者信息文件必须使用 UTF-8 编码。") from error
    if not value:
        raise ScanFailure("开发者信息文件没有可用内容。")
    if len(value) > MAX_DEVELOPER_NAME_LENGTH:
        raise ScanFailure("开发者名称不能超过 200 个字符。")
    return value


def _read_source_attribution(path: Path) -> str:
    if path.suffix.lower() not in SUPPORTED_SOURCE_INFO_FILES:
        raise ScanFailure("来源信息必须是 .txt 文件。")
    size = path.stat().st_size
    if size <= 0 or size > MAX_SOURCE_INFO_FILE_BYTES:
        raise ScanFailure("来源信息文件必须为非空且不超过 64 KB。")
    try:
        value = " ".join(path.read_text(encoding="utf-8-sig").split())
    except UnicodeDecodeError as error:
        raise ScanFailure("来源信息文件必须使用 UTF-8 编码。") from error
    if not value:
        raise ScanFailure("来源信息文件没有可用内容。")
    if len(value) > MAX_SOURCE_INFO_LENGTH:
        raise ScanFailure("来源信息不能超过 4000 个字符。")
    return value


def _summary_html(report: dict[str, Any]) -> str:
    app = report.get("app") or {}
    developer = report.get("developer") or {}
    source_attribution = report.get("sourceAttribution") or {}
    rows = [
        ("状态", report.get("status")),
        ("应用", app.get("applicationLabel")),
        ("开发者（编辑提供）", developer.get("name")),
        ("安装包来源（编辑提供）", source_attribution.get("value")),
        ("包名", app.get("packageName")),
        ("版本", app.get("versionName")),
        ("Version code", app.get("versionCode")),
        ("源文件 SHA-256", (report.get("source") or {}).get("sha256")),
        (
            "签名证书 SHA-256",
            ", ".join((report.get("signature") or {}).get("certificateSha256") or []),
        ),
    ]
    table = "".join(
        f"<tr><th>{html.escape(str(label))}</th><td>{html.escape(str(value or '未确认'))}</td></tr>"
        for label, value in rows
    )
    findings = (
        "".join(
            "<li><strong>"
            + html.escape(item.get("severity", ""))
            + "</strong> · "
            + html.escape(item.get("message", ""))
            + "</li>"
            for item in report.get("findings", [])
        )
        or "<li>没有发现阻塞项或警告。</li>"
    )
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>APKBA Intake 扫描摘要</title><style>
body{{font:15px/1.6 system-ui,sans-serif;max-width:900px;margin:40px auto;
padding:0 24px;color:#17233b}}
h1{{font-size:28px}}.badge{{display:inline-block;padding:5px 12px;
border-radius:999px;background:#e8f7f1;color:#087763}}
table{{width:100%;border-collapse:collapse;margin:24px 0}}
th,td{{padding:10px 12px;border-bottom:1px solid #dfe6ef;
text-align:left;vertical-align:top}}
th{{width:220px;color:#53627a}}code{{overflow-wrap:anywhere}}.note{{color:#53627a}}
</style></head><body><span class="badge">离线静态扫描</span><h1>Agent1 Intake 扫描摘要</h1>
<table>{table}</table><h2>发现项</h2><ul>{findings}</ul>
<p class="note">本报告确认文件完整性、静态 manifest 与签名信息，不等同于恶意软件检测或安全承诺。</p>
</body></html>"""


def create_intake_bundle(
    report: dict[str, Any],
    source_path: str | os.PathLike[str],
    icon_path: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
    *,
    developer_path: str | os.PathLike[str] | None = None,
    source_attribution_path: str | os.PathLike[str] | None = None,
) -> Path:
    """Copy verified inputs and reports into an atomic, portable intake folder."""

    if report.get("status") == "blocked":
        raise ScanFailure("扫描存在阻塞项，未生成 Agent1 交接包。")
    source = Path(source_path).resolve()
    icon = Path(icon_path).resolve()
    developer_file = Path(developer_path).resolve() if developer_path else None
    developer_name = _read_developer_name(developer_file) if developer_file else None
    source_attribution_file = (
        Path(source_attribution_path).resolve() if source_attribution_path else None
    )
    source_attribution_value = (
        _read_source_attribution(source_attribution_file)
        if source_attribution_file
        else None
    )
    root = Path(output_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    app = report.get("app") or {}
    app_name = _portable_name(str(app.get("applicationLabel") or "Android_App"), "Android_App")
    package = _portable_name(str(app.get("packageName") or "unknown.package"), "unknown.package")
    base_name = f"{app_name}_{package}_Agent1_Intake"
    destination = _unique_destination(root, base_name)
    staging = root / f".apkba-intake-{uuid.uuid4().hex}"

    try:
        staging.mkdir()
        source_format = str((report.get("source") or {}).get("format") or "").lower()
        portable_suffix = (
            f".{source_format}"
            if source_format in {"apk", "xapk", "apkm", "apks"}
            else source.suffix.lower()
        )
        portable_source_name = _portable_name(source.stem, "source") + portable_suffix
        source_destination = staging / portable_source_name
        icon_destination = staging / f"icon{icon.suffix.lower()}"
        developer_destination = staging / "developer.txt" if developer_file else None
        source_attribution_destination = (
            staging / "source.txt" if source_attribution_file else None
        )
        shutil.copy2(source, source_destination)
        shutil.copy2(icon, icon_destination)
        if developer_file and developer_destination:
            shutil.copy2(developer_file, developer_destination)
        if source_attribution_file and source_attribution_destination:
            shutil.copy2(source_attribution_file, source_attribution_destination)
        expected_source = (report.get("source") or {}).get("sha256")
        expected_icon = (report.get("icon") or {}).get("sha256")
        if _hash_file(source_destination) != expected_source:
            raise ScanFailure("交接包内源文件 SHA-256 与扫描结果不一致。")
        if _hash_file(icon_destination) != expected_icon:
            raise ScanFailure("交接包内图标 SHA-256 与扫描结果不一致。")
        developer_record = None
        if developer_destination and developer_name:
            developer_record = {
                "name": developer_name,
                "source": "operator_provided_text_file",
                "path": developer_destination.name,
                "sha256": _hash_file(developer_destination),
            }
        source_attribution_record = None
        if source_attribution_destination and source_attribution_value:
            source_attribution_record = {
                "value": source_attribution_value,
                "source": "operator_provided_text_file",
                "path": source_attribution_destination.name,
                "sha256": _hash_file(source_attribution_destination),
            }

        portable_report = json.loads(json.dumps(report))
        portable_report["developer"] = developer_record
        portable_report["sourceAttribution"] = source_attribution_record
        portable_report["bundle"] = {
            "sourcePath": source_destination.name,
            "iconPath": icon_destination.name,
            "developerPath": developer_destination.name if developer_destination else None,
            "sourceAttributionPath": (
                source_attribution_destination.name
                if source_attribution_destination
                else None
            ),
            "reportPath": "scan_report.json",
            "handoffPath": "agent1_handoff.json",
        }
        handoff = {
            "schemaVersion": 1,
            "kind": "apkba-agent1-intake",
            "scanStatus": report.get("status"),
            "source": {
                "path": source_destination.name,
                "sha256": expected_source,
                "format": (report.get("source") or {}).get("format"),
            },
            "icon": {"path": icon_destination.name, "sha256": expected_icon},
            "developer": developer_record,
            "sourceAttribution": source_attribution_record,
            "verifiedFacts": {
                "app": report.get("app"),
                "signature": report.get("signature"),
                "xapk": report.get("xapk"),
            },
            "instructions": [
                "Use this folder as the Agent1 evidence root for this task.",
                "Reuse verified static facts; Agent1 remains responsible for device "
                "install, launch, media, and final evidence validation.",
                "Do not infer safety or store provenance from this static scan.",
            ],
        }
        (staging / "scan_report.json").write_text(
            json.dumps(portable_report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        (staging / "agent1_handoff.json").write_text(
            json.dumps(handoff, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        (staging / "scan_summary.html").write_text(_summary_html(portable_report), encoding="utf-8")
        (staging / "README.txt").write_text(
            "APKBA Agent1 intake bundle\n\n"
            "This folder contains one original APK/XAPK/APKM/APKS, one validated icon, "
            "optional editor-provided developer and source information, "
            "and the offline scan records.\n"
            "Point Agent1 at this folder. Agent1 still performs installation, launch, "
            "manual media collection, and final evidence validation.\n",
            encoding="utf-8",
        )
        destination = _publish_staging_directory(staging, root, base_name, destination)
        return destination
    except Exception:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        raise
