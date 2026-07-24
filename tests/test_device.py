from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path

import pytest

from apkba_analyzer.device import AdbClient, prepare_bundle, select_xapk_splits
from apkba_analyzer.models import ScanFailure


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
        if arguments[:2] == ["install", "-r"]:
            return completed("Success\n" if self.install_ok else "Failure [INSTALL_FAILED]\n", 0)
        if arguments[:2] == ["install-multiple", "-r"]:
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
    assert pending["schema_version"] == 2
    assert pending["capture_mode"] == "manual"
    assert pending["device"]["serial"] == "PHONE-1"
    assert pending["media_baseline"]["device_epoch_seconds"] == 1770000000
    assert all(serial == "PHONE-1" for serial, _arguments in adb.calls)
    flattened = " ".join(" ".join(arguments) for _serial, arguments in adb.calls)
    assert "screencap" not in flattened
    assert "screenrecord" not in flattened


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
