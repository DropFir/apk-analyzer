"""Command-line and GUI dispatch."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from apkba_analyzer.device import AdbClient, scan_create_and_prepare
from apkba_analyzer.finish import finalize_evidence, finish_preflight
from apkba_analyzer.intake import create_intake_bundle
from apkba_analyzer.models import ScanFailure
from apkba_analyzer.scanner import scan_package


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="APKBA offline APK/XAPK intake analyzer")
    subparsers = parser.add_subparsers(dest="command")
    scan = subparsers.add_parser("scan", help="scan and create an Agent1 intake folder")
    scan.add_argument("--source", required=True, type=Path)
    scan.add_argument("--icon", required=True, type=Path)
    scan.add_argument("--developer", type=Path)
    scan.add_argument("--source-info", type=Path)
    scan.add_argument("--output", required=True, type=Path)
    scan.add_argument("--profile", choices=("standard", "quick"), default="standard")
    scan.add_argument("--report-only", action="store_true")
    prepare = subparsers.add_parser(
        "prepare", help="scan, install on one explicit device, launch, and create media baseline"
    )
    prepare.add_argument("--source", required=True, type=Path)
    prepare.add_argument("--icon", required=True, type=Path)
    prepare.add_argument("--developer", type=Path)
    prepare.add_argument("--source-info", type=Path)
    prepare.add_argument("--output", required=True, type=Path)
    prepare.add_argument("--serial", required=True)
    prepare.add_argument(
        "--allow-low-target-sdk-bypass",
        action="store_true",
        help="explicitly allow ADB's low-target-SDK compatibility install on the test device",
    )
    preflight = subparsers.add_parser(
        "finish-preflight",
        help="freeze the capture boundary and list media candidates",
    )
    preflight.add_argument("--bundle", required=True, type=Path)
    finish = subparsers.add_parser(
        "finish",
        help="create and validate a schema-3 evidence package from confirmed media",
    )
    finish.add_argument("--bundle", required=True, type=Path)
    finish.add_argument("--output", type=Path)
    finish.add_argument("--screenshot", action="append", default=[])
    finish.add_argument("--recording", required=True)
    finish.add_argument(
        "--visibility",
        required=True,
        choices=(
            "visible",
            "protected_black_screen",
            "partially_visible_protected_content",
        ),
    )
    finish.add_argument(
        "--review-method",
        required=True,
        choices=(
            "representative_frame_visual_review",
            "operator_confirmed_playback",
            "representative_frame_and_operator_report",
        ),
    )
    finish.add_argument("--operator-reported-protected-media", action="store_true")
    finish.add_argument("--restriction-image", type=Path)
    finish.add_argument("--review-frame", action="append", type=Path, default=[])
    subparsers.add_parser("devices", help="list USB-debugging devices without changing them")
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
        if args.command == "devices":
            print(
                json.dumps(
                    {"devices": AdbClient().list_devices()},
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.command == "prepare":
            report, bundle, result = scan_create_and_prepare(
                args.source,
                args.icon,
                args.output,
                args.serial,
                developer_path=args.developer,
                source_attribution_path=args.source_info,
                confirm_low_target_sdk=(
                    (lambda _details: True) if args.allow_low_target_sdk_bypass else None
                ),
            )
            print(
                json.dumps(
                    {"report": report, "bundlePath": str(bundle), "prepare": result},
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.command == "finish-preflight":
            print(
                json.dumps(
                    finish_preflight(args.bundle),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.command == "finish":
            missing_frames = [path for path in args.review_frame if not path.is_file()]
            if missing_frames:
                raise ScanFailure(f"代表帧不存在：{missing_frames[0]}")
            result = finalize_evidence(
                args.bundle,
                args.screenshot,
                args.recording,
                content_visibility=args.visibility,
                review_method=args.review_method,
                operator_reported_protected_media=(
                    args.operator_reported_protected_media
                ),
                local_restriction_image=args.restriction_image,
                output_root=args.output,
                review={
                    "recordingFrames": [str(path.resolve()) for path in args.review_frame],
                    "selectedRecording": {"remote_path": args.recording},
                },
            )
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        report = scan_package(args.source, args.icon, profile=args.profile)
        payload: dict[str, object] = {"report": report}
        if report["status"] != "blocked" and not args.report_only:
            payload["bundlePath"] = str(
                create_intake_bundle(
                    report,
                    args.source,
                    args.icon,
                    args.output,
                    developer_path=args.developer,
                    source_attribution_path=args.source_info,
                )
            )
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 2 if report["status"] == "blocked" else 0
    except (OSError, ScanFailure) as error:
        print(json.dumps({"status": "failed", "error": str(error)}, ensure_ascii=False))
        return 1
