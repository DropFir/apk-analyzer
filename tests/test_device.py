from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path

import pytest

from apkba_analyzer.device import (
    AdbClient,
    device_session_lock,
    ensure_native_abi_compatible,
    low_target_sdk_install_requirement,
    prepare_bundle,
    record_media_capture_end,
    scan_create_and_prepare,
    select_xapk_splits,
)
from apkba_analyzer.models import ScanFailure
from apkba_analyzer.scanner import _hash_file


def completed(stdout: str = "", returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_list_devices_parses_online_and_unauthorized(tmp_path: Path) -> None:
    def runner(command, **_kwargs):
        assert command[-2:] == ["devices", "-l"]
        return completed(
            "List of devices attached\n"
            "ABC123 device product:gta model:Galaxy_Tab device:gta transport_id:1\n"
            "WAITING unauthorized usb:1-2 transport_id:2\n"
        )

    devices = AdbClient(tmp_path / "adb", runner=runner).list_devices()

    assert devices[0]["serial"] == "ABC123"
    assert devices[0]["model"] == "Galaxy_Tab"
    assert devices[1]["state"] == "unauthorized"


def test_device_command_is_explicitly_scoped_by_serial(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def runner(command, **_kwargs):
        calls.append(command)
        return completed("Success\n")

    client = AdbClient(tmp_path / "adb", runner=runner)
    client.invoke(["install", "-r", "app.apk"], serial="PHONE-7")

    assert calls == [[str(tmp_path / "adb"), "-s", "PHONE-7", "install", "-r", "app.apk"]]


def test_device_session_lock_is_per_serial_and_cross_window_safe(tmp_path: Path) -> None:
    with device_session_lock("PHONE-A", lock_root=tmp_path):
        with (
            pytest.raises(ScanFailure, match="另一个 APKBA 窗口"),
            device_session_lock("PHONE-A", lock_root=tmp_path),
        ):
            pass
        with device_session_lock("PHONE-B", lock_root=tmp_path):
            pass


def test_prepare_workflow_refuses_a_device_reserved_by_another_window(
    tmp_path: Path,
) -> None:
    serial = "APKBA-TEST-RESERVED-PHONE"
    with (
        device_session_lock(serial),
        pytest.raises(ScanFailure, match="另一个 APKBA 窗口"),
    ):
        scan_create_and_prepare(
            tmp_path / "missing.apk",
            tmp_path / "missing.webp",
            tmp_path,
            serial,
        )


def test_prepare_workflow_reports_the_actual_static_blocker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "apkba_analyzer.device.scan_package",
        lambda *_args, **_kwargs: {
            "status": "blocked",
            "blockers": ["该 APK 是需要配套 split 的 base APK，不能单独安装。"],
        },
    )

    with pytest.raises(ScanFailure, match="需要配套 split"):
        scan_create_and_prepare(
            tmp_path / "base.apk",
            tmp_path / "icon.webp",
            tmp_path,
            "APKBA-TEST-BLOCKED-PHONE",
        )


def test_select_xapk_uses_supported_32_bit_abi_and_nearest_density() -> None:
    xapk = {
        "baseApk": "base.apk",
        "splits": [
            {"id": "base", "file": "base.apk"},
            {"id": "config.armeabi_v7a", "file": "arm32.apk"},
            {"id": "config.x86", "file": "x86.apk"},
            {"id": "config.xhdpi", "file": "xhdpi.apk"},
            {"id": "config.xxhdpi", "file": "xxhdpi.apk"},
            {"id": "config.en", "file": "en.apk"},
            {"id": "feature_camera", "file": "camera.apk"},
        ],
    }
    device = {
        "supported_abis": ["arm64-v8a", "armeabi-v7a"],
        "density_dpi": 440,
        "locale": "en-US",
    }

    assert select_xapk_splits(xapk, device) == [
        "base.apk",
        "arm32.apk",
        "xxhdpi.apk",
        "en.apk",
        "camera.apk",
    ]


def test_select_xapk_rejects_incompatible_abi() -> None:
    with pytest.raises(ScanFailure, match="不兼容"):
        select_xapk_splits(
            {
                "baseApk": "base.apk",
                "splits": [
                    {"id": "base", "file": "base.apk"},
                    {"id": "config.x86", "file": "x86.apk"},
                ],
            },
            {"supported_abis": ["arm64-v8a"]},
        )


def test_native_abi_check_rejects_x86_64_apk_on_arm_phone() -> None:
    report = {
        "app": {
            "nativeCode": {
                "libraryCount": 1,
                "abis": ["x86_64"],
                "unknownAbiDirectories": [],
            }
        }
    }

    with pytest.raises(ScanFailure, match="安装包 ABI：x86_64"):
        ensure_native_abi_compatible(
            report,
            {"supported_abis": ["arm64-v8a", "armeabi-v7a"]},
        )


def test_native_abi_check_accepts_matching_or_managed_only_apk() -> None:
    ensure_native_abi_compatible(
        {"app": {"nativeCode": {"libraryCount": 1, "abis": ["x86_64"]}}},
        {"supported_abis": ["x86_64", "x86"]},
    )
    ensure_native_abi_compatible(
        {"app": {"nativeCode": {"libraryCount": 0, "abis": []}}},
        {"supported_abis": ["arm64-v8a"]},
    )


def test_select_apkm_matches_feature_module_configs() -> None:
    bundle = {
        "baseApk": "base.apk",
        "splits": [
            {"id": "base", "file": "base.apk"},
            {"id": "camera", "file": "split_camera.apk"},
            {
                "id": "camera.config.arm64_v8a",
                "file": "split_camera.config.arm64_v8a.apk",
            },
            {"id": "camera.config.x86", "file": "split_camera.config.x86.apk"},
            {
                "id": "camera.config.xxhdpi",
                "file": "split_camera.config.xxhdpi.apk",
            },
            {"id": "camera.config.en", "file": "split_camera.config.en.apk"},
        ],
    }
    device = {
        "supported_abis": ["arm64-v8a"],
        "density_dpi": 420,
        "locale": "en-US",
    }

    assert select_xapk_splits(bundle, device) == [
        "base.apk",
        "split_camera.config.arm64_v8a.apk",
        "split_camera.config.xxhdpi.apk",
        "split_camera.config.en.apk",
        "split_camera.apk",
    ]


class FakePrepareAdb:
    def __init__(self, *, install_ok: bool = True, exact_launch_ok: bool = True):
        self.install_ok = install_ok
        self.exact_launch_ok = exact_launch_ok
        self.calls: list[tuple[str | None, list[str]]] = []

    def invoke(
        self,
        arguments: list[str],
        *,
        serial: str | None = None,
        allow_failure: bool = False,
        timeout: int = 120,
    ):
        self.calls.append((serial, arguments))
        if arguments[:3] == ["shell", "pm", "path"]:
            return completed("", 1)
        if arguments[0] == "install":
            return completed("Success\n" if self.install_ok else "Failure [INSTALL_FAILED]\n", 0)
        if arguments[0] == "install-multiple":
            return completed("Success\n" if self.install_ok else "Failure [INSTALL_FAILED]\n", 0)
        if arguments[:4] == ["shell", "am", "start", "-n"]:
            return completed("Starting\n" if self.exact_launch_ok else "Error: bad activity\n")
        if arguments[:2] == ["shell", "monkey"]:
            return completed("Events injected: 1\n")
        raise AssertionError(arguments)

    def device_facts(self, serial: str):
        return {
            "serial": serial,
            "model": "Test Phone",
            "abi": "arm64-v8a",
            "supported_abis": ["arm64-v8a", "armeabi-v7a"],
            "sdk": "35",
            "locale": "en-US",
            "density_dpi": 420,
        }

    def focused_activity(self, _serial: str):
        return "com.example.app/.MainActivity"

    def visible_ui_texts(self, _serial: str):
        return []

    def media_snapshot(self, _serial: str):
        return {
            "device_epoch": 1770000000,
            "device_time": "2026-07-23T10:00:00+0800",
            "screenshots": [],
            "recordings": [],
        }


class FakeCaptureEndAdb:
    def device_facts(self, serial: str):
        return {"serial": serial, "model": "Test Phone"}

    def focused_activity(self, _serial: str):
        return "com.example.app/.DetailsActivity"

    def media_snapshot(self, _serial: str):
        return {
            "device_epoch": 1770000100,
            "device_time": "2026-07-23T10:01:40+0800",
            "screenshots": [
                {
                    "modified_epoch_seconds": 1769999999.0,
                    "size_bytes": 10,
                    "remote_path": "/sdcard/DCIM/Screenshots/old.png",
                },
                {
                    "modified_epoch_seconds": 1770000010.0,
                    "size_bytes": 20,
                    "remote_path": "/sdcard/DCIM/Screenshots/current.png",
                },
            ],
            "recordings": [
                {
                    "modified_epoch_seconds": 1770000020.0,
                    "size_bytes": 30,
                    "remote_path": "/sdcard/DCIM/Screen recordings/current.mp4",
                }
            ],
        }


def make_bundle(tmp_path: Path) -> tuple[dict, Path]:
    bundle = tmp_path / "Intake"
    bundle.mkdir()
    (bundle / "app.apk").write_bytes(b"test")
    (bundle / "icon.png").write_bytes(b"icon")
    handoff = {
        "source": {
            "path": "app.apk",
            "sha256": "abc123",
            "format": "apk",
        },
        "icon": {"path": "icon.png"},
    }
    (bundle / "agent1_handoff.json").write_text(json.dumps(handoff), encoding="utf-8")
    report = {
        "app": {
            "packageName": "com.example.app",
            "applicationLabel": "Example",
            "versionName": "1.0",
            "versionCode": 1,
            "minSdk": 23,
            "targetSdk": 35,
            "launcherActivity": ".MainActivity",
            "permissions": [],
        }
    }
    return report, bundle


def test_prepare_writes_agent1_pending_session_without_capturing_media(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report, bundle = make_bundle(tmp_path)
    adb = FakePrepareAdb()
    monkeypatch.setattr("apkba_analyzer.device.time.sleep", lambda _value: None)

    result = prepare_bundle(report, bundle, "PHONE-1", adb=adb)

    pending = json.loads((bundle / ".apkba-pending-session.json").read_text(encoding="utf-8"))
    assert result["status"] == "awaiting_manual_capture"
    assert result["deviceSerial"] == "PHONE-1"
    assert pending["schema_version"] == 2
    assert pending["capture_mode"] == "manual"
    assert pending["device"]["serial"] == "PHONE-1"
    assert pending["media_baseline"]["device_epoch_seconds"] == 1770000000
    assert all(serial == "PHONE-1" for serial, _arguments in adb.calls)
    flattened = " ".join(" ".join(arguments) for _serial, arguments in adb.calls)
    assert "screencap" not in flattened
    assert "screenrecord" not in flattened


def test_prepare_blocks_incompatible_native_abi_before_install_or_phone_write(
    tmp_path: Path,
) -> None:
    report, bundle = make_bundle(tmp_path)
    report["app"]["nativeCode"] = {
        "libraryCount": 1,
        "abis": ["x86_64"],
        "unknownAbiDirectories": [],
    }
    adb = FakePrepareAdb()
    device = adb.device_facts("PHONE-ARM")

    with pytest.raises(ScanFailure, match="安装包原生库与目标手机 CPU 架构不兼容"):
        prepare_bundle(report, bundle, "PHONE-ARM", adb=adb, device=device)

    assert adb.calls == []
    assert not (bundle / ".apkba-pending-session.json").exists()


def test_prepare_carries_optional_developer_into_pending_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report, bundle = make_bundle(tmp_path)
    developer = bundle / "developer.txt"
    developer.write_text("SEGA\n", encoding="utf-8")
    handoff_path = bundle / "agent1_handoff.json"
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    handoff["developer"] = {
        "name": "SEGA",
        "source": "operator_provided_text_file",
        "path": developer.name,
        "sha256": _hash_file(developer),
    }
    handoff_path.write_text(json.dumps(handoff), encoding="utf-8")
    monkeypatch.setattr("apkba_analyzer.device.time.sleep", lambda _value: None)

    prepare_bundle(report, bundle, "PHONE-DEV", adb=FakePrepareAdb())

    pending = json.loads((bundle / ".apkba-pending-session.json").read_text(encoding="utf-8"))
    assert pending["developer"]["name"] == "SEGA"
    assert pending["developer"]["file_name"] == "developer.txt"
    assert pending["app"]["developer_name"] == "SEGA"
    assert pending["app"]["developer_source"] == "operator_provided_text_file"


def test_low_target_sdk_requirement_matches_android_15_install_policy() -> None:
    requirement = low_target_sdk_install_requirement(
        {"app": {"packageName": "com.example.legacy", "targetSdk": 22}},
        {"sdk": "35"},
    )

    assert requirement == {
        "package_name": "com.example.legacy",
        "target_sdk": 22,
        "device_sdk": 35,
        "device_minimum_target_sdk": 24,
        "reason": "android_low_target_sdk_install_block",
    }
    assert (
        low_target_sdk_install_requirement(
            {"app": {"packageName": "com.example.current", "targetSdk": 24}},
            {"sdk": "35"},
        )
        is None
    )


def test_prepare_requires_explicit_low_target_sdk_confirmation_before_creating_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report, _bundle = make_bundle(tmp_path)
    report["status"] = "pass"
    report["app"]["targetSdk"] = 22
    adb = FakePrepareAdb()
    monkeypatch.setattr("apkba_analyzer.device.scan_package", lambda *_args, **_kwargs: report)
    monkeypatch.setattr(
        "apkba_analyzer.device.create_intake_bundle",
        lambda *_args, **_kwargs: pytest.fail("bundle must not be created before confirmation"),
    )

    with pytest.raises(ScanFailure, match="已取消低目标 SDK 兼容安装"):
        scan_create_and_prepare(
            tmp_path / "legacy.apk",
            tmp_path / "legacy.webp",
            tmp_path,
            "PHONE-LEGACY",
            adb=adb,
        )

    assert not any(arguments[0].startswith("install") for _serial, arguments in adb.calls)


def test_prepare_uses_and_records_explicit_low_target_sdk_bypass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report, bundle = make_bundle(tmp_path)
    report["app"]["targetSdk"] = 22
    adb = FakePrepareAdb()
    monkeypatch.setattr("apkba_analyzer.device.time.sleep", lambda _value: None)
    requirement = low_target_sdk_install_requirement(report, adb.device_facts("PHONE-LEGACY"))
    assert requirement is not None
    bypass = {**requirement, "authorization": "explicit_operator_confirmation"}

    result = prepare_bundle(
        report,
        bundle,
        "PHONE-LEGACY",
        adb=adb,
        device=adb.device_facts("PHONE-LEGACY"),
        low_target_sdk_bypass=bypass,
    )

    install = next(arguments for _serial, arguments in adb.calls if arguments[0] == "install")
    pending = json.loads((bundle / ".apkba-pending-session.json").read_text(encoding="utf-8"))
    assert install[:3] == ["install", "--bypass-low-target-sdk-block", "-r"]
    assert result["lowTargetSdkBypassUsed"] is True
    assert pending["install"]["low_target_sdk_bypass_used"] is True
    assert pending["install"]["low_target_sdk_bypass"]["target_sdk"] == 22


def test_prepare_workflow_continues_after_explicit_low_target_sdk_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report, bundle = make_bundle(tmp_path)
    report["status"] = "pass"
    report["app"]["targetSdk"] = 22
    adb = FakePrepareAdb()
    confirmations: list[dict] = []
    monkeypatch.setattr("apkba_analyzer.device.scan_package", lambda *_args, **_kwargs: report)
    monkeypatch.setattr(
        "apkba_analyzer.device.create_intake_bundle",
        lambda *_args, **_kwargs: bundle,
    )
    monkeypatch.setattr("apkba_analyzer.device.time.sleep", lambda _value: None)

    _report, prepared_bundle, result = scan_create_and_prepare(
        tmp_path / "legacy.apk",
        tmp_path / "legacy.webp",
        tmp_path,
        "PHONE-LEGACY",
        adb=adb,
        confirm_low_target_sdk=lambda details: confirmations.append(details) or True,
    )

    install = next(arguments for _serial, arguments in adb.calls if arguments[0] == "install")
    assert prepared_bundle == bundle
    assert len(confirmations) == 1
    assert confirmations[0]["target_sdk"] == 22
    assert install[:3] == ["install", "--bypass-low-target-sdk-block", "-r"]
    assert result["lowTargetSdkBypassUsed"] is True


def test_record_media_capture_end_adds_a_bounded_snapshot_without_closing_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report, bundle = make_bundle(tmp_path)
    monkeypatch.setattr("apkba_analyzer.device.time.sleep", lambda _value: None)
    prepare_bundle(report, bundle, "PHONE-1", adb=FakePrepareAdb())

    result = record_media_capture_end(bundle, "PHONE-1", adb=FakeCaptureEndAdb())

    pending = json.loads((bundle / ".apkba-pending-session.json").read_text(encoding="utf-8"))
    capture_end = pending["media_capture_end"]
    assert pending["status"] == "awaiting_manual_capture"
    assert capture_end["device_epoch_seconds"] == 1770000100
    assert capture_end["screenshot_count"] == 1
    assert capture_end["recording_count"] == 1
    assert capture_end["screenshots"][0]["remote_path"].endswith("current.png")
    assert result["status"] == "capture_end_recorded"
    assert result["deviceSerial"] == "PHONE-1"


def test_record_media_capture_end_rejects_a_different_device(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report, bundle = make_bundle(tmp_path)
    monkeypatch.setattr("apkba_analyzer.device.time.sleep", lambda _value: None)
    prepare_bundle(report, bundle, "PHONE-1", adb=FakePrepareAdb())

    with pytest.raises(ScanFailure, match="绑定的是手机 PHONE-1"):
        record_media_capture_end(bundle, "PHONE-2", adb=FakeCaptureEndAdb())


def test_prepare_uses_one_monkey_fallback_for_rejected_component(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report, bundle = make_bundle(tmp_path)
    adb = FakePrepareAdb(exact_launch_ok=False)
    monkeypatch.setattr("apkba_analyzer.device.time.sleep", lambda _value: None)

    prepare_bundle(report, bundle, "PHONE-2", adb=adb)

    monkey_calls = [args for _serial, args in adb.calls if args[:2] == ["shell", "monkey"]]
    assert len(monkey_calls) == 1


def test_prepare_installs_apkm_with_install_multiple(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report, bundle = make_bundle(tmp_path)
    source = bundle / "app.apkm"
    (bundle / "app.apk").unlink()

    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("base.apk", b"base")
        archive.writestr("split_config.arm64_v8a.apk", b"arm64")
    handoff_path = bundle / "agent1_handoff.json"
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    handoff["source"].update({"path": source.name, "format": "apkm"})
    handoff_path.write_text(json.dumps(handoff), encoding="utf-8")
    report["xapk"] = {
        "baseApk": "base.apk",
        "splits": [
            {"id": "base", "file": "base.apk"},
            {"id": "config.arm64_v8a", "file": "split_config.arm64_v8a.apk"},
        ],
    }
    adb = FakePrepareAdb()
    monkeypatch.setattr("apkba_analyzer.device.time.sleep", lambda _value: None)

    prepare_bundle(report, bundle, "PHONE-APKM", adb=adb)

    install = next(
        arguments for _serial, arguments in adb.calls if arguments[0] == "install-multiple"
    )
    assert install[:2] == ["install-multiple", "-r"]
    assert {Path(path).name for path in install[2:]} == {
        "base.apk",
        "split_config.arm64_v8a.apk",
    }


def test_install_failure_stops_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report, bundle = make_bundle(tmp_path)
    adb = FakePrepareAdb(install_ok=False)
    monkeypatch.setattr("apkba_analyzer.device.time.sleep", lambda _value: None)

    with pytest.raises(ScanFailure, match="不会自动卸载"):
        prepare_bundle(report, bundle, "PHONE-3", adb=adb)

    assert not (bundle / ".apkba-pending-session.json").exists()
    assert not any(args[:2] in (["shell", "am"], ["shell", "monkey"]) for _, args in adb.calls)
