from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from PIL import Image

from apkba_analyzer.finish import (
    _visibility_suggestion,
    finalize_evidence,
    finish_preflight,
    validate_evidence_package,
)
from apkba_analyzer.models import ScanFailure
from apkba_analyzer.scanner import _hash_file


def completed(stdout: str = "", returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def fake_mp4() -> bytes:
    return b"\x00\x00\x00\x18ftypmp42" + b"\0" * 1100 + b"moov" + b"mdat"


class FakeFinishAdb:
    def __init__(self, remote_files: dict[str, Path]):
        self.remote_files = remote_files
        self.calls: list[tuple[str | None, list[str]]] = []

    def device_facts(self, serial: str):
        return {"serial": serial, "model": "Test Phone"}

    def invoke(
        self,
        arguments: list[str],
        *,
        serial: str | None = None,
        allow_failure: bool = False,
        timeout: int = 120,
    ):
        self.calls.append((serial, arguments))
        if arguments[0] != "pull":
            raise AssertionError(arguments)
        source = self.remote_files[arguments[1]]
        shutil.copy2(source, arguments[2])
        return completed("1 file pulled\n")


def make_finish_bundle(tmp_path: Path) -> tuple[Path, dict[str, Path]]:
    bundle = tmp_path / "Example_Agent1_Intake"
    bundle.mkdir()
    source = bundle / "app.apk"
    source.write_bytes(b"synthetic package")
    icon = bundle / "icon.png"
    Image.new("RGB", (512, 512), "#087763").save(icon)
    remote_screenshot = "/sdcard/DCIM/Screenshots/Screenshot_Example.png"
    remote_unrelated = "/sdcard/DCIM/Screenshots/Screenshot_Other.png"
    remote_recording = "/sdcard/DCIM/Screen recordings/Example.mp4"
    local_screenshot = tmp_path / "screen.png"
    local_unrelated = tmp_path / "other.png"
    local_recording = tmp_path / "recording.mp4"
    Image.new("RGB", (1080, 1920), "#123456").save(local_screenshot)
    Image.new("RGB", (1080, 1920), "#654321").save(local_unrelated)
    local_recording.write_bytes(fake_mp4())
    pending = {
        "schema_version": 2,
        "status": "awaiting_manual_capture",
        "capture_mode": "manual",
        "source_note": "User-provided package.",
        "source": {
            "path": str(source),
            "file_name": source.name,
            "format": "apk",
            "size_bytes": source.stat().st_size,
            "sha256": _hash_file(source),
            "selected_splits": [],
        },
        "icon": {"path": str(icon), "file_name": icon.name},
        "app": {
            "package_name": "com.example.app",
            "application_label": "Example",
            "application_label_source": "manifest",
            "version_name": "1.0",
            "version_code": 1,
            "min_sdk": 23,
            "target_sdk": 35,
            "launch_activity": ".MainActivity",
            "declared_permissions": ["android.permission.INTERNET"],
        },
        "device": {
            "serial": "PHONE-FINISH",
            "model": "Test Phone",
            "supported_abis": ["arm64-v8a"],
        },
        "install": {
            "result": "success",
            "method": "adb install -r",
            "installed_splits": [],
            "low_target_sdk_bypass_used": False,
        },
        "launch": {
            "result": "success",
            "method": "am_start_component",
            "component": "com.example.app/.MainActivity",
            "primary_exit_code": 0,
            "final_exit_code": 0,
            "fallback_used": False,
            "reason": None,
            "focused_activity": "com.example.app/.MainActivity",
            "visible_texts": [],
        },
        "setup": {},
        "media_baseline": {
            "finished_local": "2026-07-24T10:00:00+08:00",
            "device_epoch_seconds": 1000,
        },
        "media_capture_end": {
            "status": "recorded",
            "device_epoch_seconds": 1100,
            "device_time": "2026-07-24T10:01:40+0800",
            "screenshots": [
                {
                    "modified_epoch_seconds": 1010,
                    "size_bytes": local_screenshot.stat().st_size,
                    "remote_path": remote_screenshot,
                },
                {
                    "modified_epoch_seconds": 1020,
                    "size_bytes": local_unrelated.stat().st_size,
                    "remote_path": remote_unrelated,
                },
            ],
            "recordings": [
                {
                    "modified_epoch_seconds": 1030,
                    "size_bytes": local_recording.stat().st_size,
                    "remote_path": remote_recording,
                }
            ],
        },
        "automated_prepare": {"elapsed_ms": 100},
    }
    (bundle / ".apkba-pending-session.json").write_text(
        json.dumps(pending), encoding="utf-8"
    )
    return bundle, {
        remote_screenshot: local_screenshot,
        remote_unrelated: local_unrelated,
        remote_recording: local_recording,
    }


def test_preflight_lists_every_bounded_candidate_and_suggests_attribution(
    tmp_path: Path,
) -> None:
    bundle, _remote_files = make_finish_bundle(tmp_path)

    result = finish_preflight(bundle, record_end_if_missing=False)

    assert len(result["screenshots"]) == 2
    assert len(result["recordings"]) == 1
    assert result["suggestedScreenshotPaths"] == [
        "/sdcard/DCIM/Screenshots/Screenshot_Example.png"
    ]


def test_finalize_builds_and_validates_schema3_package(tmp_path: Path) -> None:
    bundle, remote_files = make_finish_bundle(tmp_path)
    adb = FakeFinishAdb(remote_files)
    screenshot = "/sdcard/DCIM/Screenshots/Screenshot_Example.png"
    recording = "/sdcard/DCIM/Screen recordings/Example.mp4"

    result = finalize_evidence(
        bundle,
        [screenshot],
        recording,
        content_visibility="visible",
        review_method="operator_confirmed_playback",
        adb=adb,
    )

    package = Path(result["packagePath"])
    observations = json.loads((package / "observations.json").read_text(encoding="utf-8"))
    assert result["status"] == "success"
    assert observations["schema_version"] == 3
    assert observations["media"]["screenshot_count"] == 1
    assert observations["media"]["recording"]["content_visibility"] == "visible"
    assert observations["source"]["sha256"] == observations["source"]["copied_source_sha256"]
    assert (package / "videos" / "raw_install_test.mp4").is_file()
    assert not (bundle / ".apkba-pending-session.json").exists()
    assert all(serial == "PHONE-FINISH" for serial, _arguments in adb.calls)


def test_protected_operator_report_requires_protected_classification_and_frames(
    tmp_path: Path,
) -> None:
    bundle, remote_files = make_finish_bundle(tmp_path)

    with pytest.raises(ScanFailure, match="不能选择“可见”"):
        finalize_evidence(
            bundle,
            ["/sdcard/DCIM/Screenshots/Screenshot_Example.png"],
            "/sdcard/DCIM/Screen recordings/Example.mp4",
            content_visibility="visible",
            review_method="representative_frame_and_operator_report",
            operator_reported_protected_media=True,
            adb=FakeFinishAdb(remote_files),
        )


def test_protected_review_with_representative_frame_is_accepted(tmp_path: Path) -> None:
    bundle, remote_files = make_finish_bundle(tmp_path)
    screenshot = "/sdcard/DCIM/Screenshots/Screenshot_Example.png"
    recording = "/sdcard/DCIM/Screen recordings/Example.mp4"
    frame = tmp_path / "black-frame.png"
    Image.new("RGB", (400, 800), "black").save(frame)
    review = {
        "screenshots": [
            {
                "remote_path": screenshot,
                "localPath": str(remote_files[screenshot]),
            }
        ],
        "selectedRecording": {"remote_path": recording},
        "localRecordingPath": str(remote_files[recording]),
        "recordingFrames": [str(frame)],
        "recordingAuditMethod": "platform_thumbnail",
    }

    result = finalize_evidence(
        bundle,
        [screenshot],
        recording,
        content_visibility="protected_black_screen",
        review_method="representative_frame_and_operator_report",
        operator_reported_protected_media=True,
        review=review,
        adb=FakeFinishAdb(remote_files),
    )

    observations = json.loads(
        (Path(result["packagePath"]) / "observations.json").read_text(encoding="utf-8")
    )
    recording_record = observations["media"]["recording"]
    assert result["recordingStatus"] == "present_protected_black_screen"
    assert recording_record["operator_reported_protected_media"] is True
    assert recording_record["representative_frame_count"] == 1


def test_visibility_suggestion_distinguishes_black_and_visible_frames(
    tmp_path: Path,
) -> None:
    black = tmp_path / "black.png"
    visible = tmp_path / "visible.png"
    Image.new("RGB", (400, 800), "black").save(black)
    Image.new("RGB", (400, 800), "white").save(visible)

    assert _visibility_suggestion([black])[0] == "protected_black_screen"
    assert _visibility_suggestion([visible])[0] == "visible"


def test_validator_rejects_forbidden_residue(tmp_path: Path) -> None:
    bundle, remote_files = make_finish_bundle(tmp_path)
    result = finalize_evidence(
        bundle,
        ["/sdcard/DCIM/Screenshots/Screenshot_Example.png"],
        "/sdcard/DCIM/Screen recordings/Example.mp4",
        content_visibility="visible",
        review_method="operator_confirmed_playback",
        adb=FakeFinishAdb(remote_files),
    )
    package = Path(result["packagePath"])
    (package / "logs").mkdir()

    with pytest.raises(ScanFailure, match="禁止残留"):
        validate_evidence_package(package, result["sourceSha256"])
