from __future__ import annotations

import json
import zipfile
from pathlib import Path

from PIL import Image

from apkba_analyzer.scanner import scan_package

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.fixture" android:versionName="2.4.1" android:versionCode="241">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35" />
  <uses-permission android:name="android.permission.INTERNET" />
  <application android:label="Fixture App">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
  </application>
</manifest>"""

REQUIRED_SPLIT_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.fixture" android:versionName="2.4.1" android:versionCode="241"
    android:requiredSplitTypes="base__abi,base__density">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35" />
  <application android:label="Fixture App">
    <meta-data android:name="com.android.vending.splits.required" android:value="true" />
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
  </application>
</manifest>"""


def make_apk(path: Path, manifest: str = MANIFEST) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", b"fixture")


def make_icon(path: Path, size: tuple[int, int] = (512, 512)) -> None:
    Image.new("RGBA", size, (12, 128, 108, 255)).save(path)


def test_apk_scan_extracts_agent1_static_facts(tmp_path: Path) -> None:
    source = tmp_path / "fixture.apk"
    icon = tmp_path / "icon.png"
    make_apk(source)
    make_icon(icon)

    report = scan_package(source, icon, profile="quick")

    assert report["status"] in {"pass", "warning"}
    assert report["source"]["sha256"]
    assert report["app"]["packageName"] == "com.example.fixture"
    assert report["app"]["versionCode"] == 241
    assert report["app"]["launcherActivity"] == ".MainActivity"
    assert report["icon"]["square"] is True
    assert report["tools"]["manifestParser"] == "plain_xml_fixture"


def test_apk_scan_inventories_embedded_native_abis(tmp_path: Path) -> None:
    source = tmp_path / "native.apk"
    icon = tmp_path / "icon.png"
    make_apk(source)
    with zipfile.ZipFile(source, "a", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("lib/x86_64/libfixture.so", b"not executable test data")
        archive.writestr("lib/x86_64/libsecond.so", b"not executable test data")
    make_icon(icon)

    report = scan_package(source, icon, profile="quick")

    assert report["app"]["nativeCode"] == {
        "libraryCount": 2,
        "abis": ["x86_64"],
        "unknownAbiDirectories": [],
    }


def test_apk_scan_records_no_native_abi_for_managed_only_package(tmp_path: Path) -> None:
    source = tmp_path / "managed.apk"
    icon = tmp_path / "icon.png"
    make_apk(source)
    make_icon(icon)

    report = scan_package(source, icon, profile="quick")

    assert report["app"]["nativeCode"]["libraryCount"] == 0
    assert report["app"]["nativeCode"]["abis"] == []


def test_non_square_icon_blocks_bundle(tmp_path: Path) -> None:
    source = tmp_path / "fixture.apk"
    icon = tmp_path / "icon.png"
    make_apk(source)
    make_icon(icon, (512, 400))

    report = scan_package(source, icon, profile="quick")

    assert report["status"] == "blocked"
    assert any(item["code"] == "icon.not_square" for item in report["findings"])


def test_standalone_base_apk_with_required_splits_is_blocked(tmp_path: Path) -> None:
    source = tmp_path / "base.apk"
    icon = tmp_path / "icon.png"
    make_apk(source, REQUIRED_SPLIT_MANIFEST)
    make_icon(icon)

    report = scan_package(source, icon, profile="quick")

    assert report["status"] == "blocked"
    assert report["app"]["splitRequired"] is True
    assert report["app"]["requiredSplitTypes"] == ["base__abi", "base__density"]
    finding = next(
        item for item in report["findings"] if item["code"] == "manifest.required_splits_missing"
    )
    assert "CPU 架构" in finding["message"]
    assert "屏幕密度" in finding["message"]


def test_xapk_inventory_and_base_manifest(tmp_path: Path) -> None:
    base = tmp_path / "base.apk"
    split = tmp_path / "config.arm64_v8a.apk"
    source = tmp_path / "fixture.xapk"
    icon = tmp_path / "icon.png"
    make_apk(
        base,
        REQUIRED_SPLIT_MANIFEST.replace(
            "base__abi,base__density",
            "base__abi",
        ),
    )
    make_apk(split, MANIFEST.replace("<manifest ", '<manifest split="config.arm64_v8a" '))
    xapk_manifest = {
        "xapk_version": 2,
        "name": "Fixture App",
        "package_name": "com.example.fixture",
        "version_name": "2.4.1",
        "version_code": "241",
        "min_sdk_version": "23",
        "target_sdk_version": "35",
        "permissions": ["android.permission.INTERNET"],
        "split_apks": [
            {"id": "base", "file": "base.apk"},
            {"id": "config.arm64_v8a", "file": "config.arm64_v8a.apk"},
        ],
    }
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(xapk_manifest))
        archive.write(base, "base.apk")
        archive.write(split, "config.arm64_v8a.apk")
    make_icon(icon)

    report = scan_package(source, icon, profile="quick")

    assert report["app"]["packageName"] == "com.example.fixture"
    assert report["xapk"]["baseApk"] == "base.apk"
    assert len(report["xapk"]["splits"]) == 2
    assert all(row["sha256"] for row in report["xapk"]["splits"])
    assert report["app"]["splitRequired"] is True
    assert not any(
        item["code"] == "manifest.required_splits_missing" for item in report["findings"]
    )


def test_xapk_saved_with_apk_extension_is_detected_from_contents(tmp_path: Path) -> None:
    base = tmp_path / "base.apk"
    split = tmp_path / "config.arm64_v8a.apk"
    source = tmp_path / "downloaded_pending.apk"
    icon = tmp_path / "icon.png"
    make_apk(base)
    make_apk(split, MANIFEST.replace("<manifest ", '<manifest split="config.arm64_v8a" '))
    xapk_manifest = {
        "xapk_version": 2,
        "name": "Fixture App",
        "package_name": "com.example.fixture",
        "version_name": "2.4.1",
        "version_code": "241",
        "split_apks": [
            {"id": "base", "file": "base.apk"},
            {"id": "config.arm64_v8a", "file": "config.arm64_v8a.apk"},
        ],
    }
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(xapk_manifest))
        archive.write(base, "base.apk")
        archive.write(split, "config.arm64_v8a.apk")
    make_icon(icon)

    report = scan_package(source, icon, profile="quick")

    assert report["source"]["format"] == "xapk"
    assert report["source"]["declaredFormat"] == "apk"
    assert report["app"]["packageName"] == "com.example.fixture"
    assert report["xapk"]["baseApk"] == "base.apk"
    assert any(
        item["code"] == "source.extension_mismatch" for item in report["findings"]
    )


def test_apkm_inventory_and_base_manifest(tmp_path: Path) -> None:
    base = tmp_path / "base.apk"
    split = tmp_path / "split_config.arm64_v8a.apk"
    source = tmp_path / "fixture.apkm"
    icon = tmp_path / "icon.png"
    make_apk(base)
    make_apk(split, MANIFEST.replace("<manifest ", '<manifest split="config.arm64_v8a" '))
    metadata = {
        "apkm_version": 3,
        "app_name": "Fixture App",
        "pname": "com.example.fixture",
        "versioncode": "241",
    }
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("info.json", json.dumps(metadata))
        archive.write(base, "base.apk")
        archive.write(split, split.name)
    make_icon(icon)

    report = scan_package(source, icon, profile="quick")

    assert report["source"]["format"] == "apkm"
    assert report["app"]["packageName"] == "com.example.fixture"
    assert report["xapk"]["bundleFormat"] == "apkm"
    assert report["xapk"]["baseApk"] == "base.apk"
    assert [row["id"] for row in report["xapk"]["splits"]] == [
        "base",
        "config.arm64_v8a",
    ]


def test_archive_traversal_is_blocked(tmp_path: Path) -> None:
    source = tmp_path / "unsafe.apk"
    icon = tmp_path / "icon.png"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
        archive.writestr("../escape", b"no")
    make_icon(icon)

    report = scan_package(source, icon, profile="quick")

    assert report["status"] == "blocked"
    assert any(item["code"] == "archive.unsafe_paths" for item in report["findings"])
