"""Command-line and GUI dispatch."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from apkba_analyzer.intake import create_intake_bundle
from apkba_analyzer.models import ScanFailure
from apkba_analyzer.scanner import scan_package


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="APKBA offline APK/XAPK intake analyzer")
    subparsers = parser.add_subparsers(dest="command")
    scan = subparsers.add_parser("scan", help="scan and create an Agent1 intake folder")
    scan.add_argument("--source", required=True, type=Path)
    scan.add_argument("--icon", required=True, type=Path)
    scan.add_argument("--output", required=True, type=Path)
    scan.add_argument("--profile", choices=("standard", "quick"), default="standard")
    scan.add_argument("--report-only", action="store_true")
    subparsers.add_parser("gui", help="open the desktop application")
    return parser


def _run_gui() -> int:
    try:
        from apkba_analyzer.app import run
    except ImportError as error:
        print(f"PySide6 GUI unavailable: {error}", file=sys.stderr)
        return 1
    return run()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command in (None, "gui"):
        return _run_gui()
    try:
        report = scan_package(args.source, args.icon, profile=args.profile)
        payload: dict[str, object] = {"report": report}
        if report["status"] != "blocked" and not args.report_only:
            payload["bundlePath"] = str(
                create_intake_bundle(report, args.source, args.icon, args.output)
            )
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 2 if report["status"] == "blocked" else 0
    except (OSError, ScanFailure) as error:
        print(json.dumps({"status": "failed", "error": str(error)}, ensure_ascii=False))
        return 1
