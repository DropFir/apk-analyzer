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

TV_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.tv" android:versionName="1.0" android:versionCode="1">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35" />
  <uses-feature android:name="android.hardware.touchscreen" android:required="false" />
  <uses-feature android:name="android.software.leanback" android:required="true" />
  <application android:label="TV Fixture">
    <activity android:name=".TvActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LEANBACK_LAUNCHER" />
      </intent-filter>
    </activity>
  </application>
</manifest>"""

MISSING_TARGET_SDK_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.ancient" android:versionName="1.0" android:versionCode="1">
  <application android:label="Ancient Fixture">
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


def test_apk_scan_recognizes_tv_only_leanback_launcher(tmp_path: Path) -> None:
    source = tmp_path / "tv.apk"
    icon = tmp_path / "icon.png"
    make_apk(source, TV_MANIFEST)
    make_icon(icon)

    report = scan_package(source, icon, profile="quick")

    assert report["status"] == "warning"
    assert report["app"]["launcherActivity"] == ".TvActivity"
    assert (
        report["app"]["launcherCategory"]
        == "android.intent.category.LEANBACK_LAUNCHER"
    )
    assert report["app"]["requiredFeatures"] == ["android.software.leanback"]
    assert any(
        item["code"] == "manifest.leanback_launcher_only"
        for item in report["findings"]
    )
    assert not any(
        item["code"] == "manifest.launcher_missing" for item in report["findings"]
    )


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


def test_apk_scan_warns_when_manifest_does_not_declare_target_sdk(
    tmp_path: Path,
) -> None:
    source = tmp_path / "ancient.apk"
    icon = tmp_path / "icon.png"
    make_apk(source, MISSING_TARGET_SDK_MANIFEST)
    make_icon(icon)

    report = scan_package(source, icon, profile="quick")

    assert report["status"] == "warning"
    assert report["app"]["targetSdk"] is None
    assert any(
        item["code"] == "manifest.target_sdk_missing" for item in report["findings"]
    )


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


def test_xapk_saved_with_apks_extension_is_detected_from_contents(tmp_path: Path) -> None:
    base = tmp_path / "hu.gabor.carculator.apk"
    density = tmp_path / "config.mdpi.apk"
    source = tmp_path / "carculator_1.0.apks"
    icon = tmp_path / "icon.png"
    make_apk(base)
    make_apk(density, MANIFEST.replace("<manifest ", '<manifest split="config.mdpi" '))
    xapk_manifest = {
        "xapk_version": 2,
        "name": "CarCulator",
        "package_name": "com.example.fixture",
        "version_name": "2.4.1",
        "version_code": "241",
        "split_apks": [
            {"id": "base", "file": base.name},
            {"id": "config.mdpi", "file": density.name},
        ],
    }
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(xapk_manifest))
        archive.write(base, base.name)
        archive.write(density, density.name)
    make_icon(icon)

    report = scan_package(source, icon, profile="quick")

    assert report["source"]["format"] == "xapk"
    assert report["source"]["declaredFormat"] == "apks"
    assert report["app"]["applicationLabel"] == "CarCulator"
    assert report["xapk"]["baseApk"] == base.name
    assert [row["id"] for row in report["xapk"]["splits"]] == [
        "base",
        "config.mdpi",
    ]
    assert any(
        item["code"] == "source.extension_mismatch" for item in report["findings"]
    )


def test_xapk_without_manifest_is_inferred_from_inner_apk_manifests(
    tmp_path: Path,
) -> None:
    source = tmp_path / "raw-splits.xapk"
    icon = tmp_path / "icon.png"
    base = tmp_path / "com.example.fixture.apk"
    arm64 = tmp_path / "config.arm64_v8a.apk"
    xxhdpi = tmp_path / "config.xxhdpi.apk"
    make_apk(base, REQUIRED_SPLIT_MANIFEST)
    make_apk(
        arm64,
        MANIFEST.replace("<manifest ", '<manifest split="config.arm64_v8a" '),
    )
    make_apk(
        xxhdpi,
        MANIFEST.replace("<manifest ", '<manifest split="config.xxhdpi" '),
    )
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(base, base.name)
        archive.write(arm64, arm64.name)
        archive.write(xxhdpi, xxhdpi.name)
    make_icon(icon)

    report = scan_package(source, icon, profile="quick")

    assert report["status"] == "warning"
    assert report["app"]["packageName"] == "com.example.fixture"
    assert report["xapk"]["bundleFormat"] == "manifest_inferred_xapk"
    assert report["xapk"]["manifestInferred"] is True
    assert report["xapk"]["baseApk"] == base.name
    assert [row["id"] for row in report["xapk"]["splits"]] == [
        "base",
        "config.arm64_v8a",
        "config.xxhdpi",
    ]
    assert any(
        item["code"] == "xapk.manifest_inferred" for item in report["findings"]
    )
    assert not report["blockers"]


def test_xapk_without_manifest_blocks_mismatched_inner_package(tmp_path: Path) -> None:
    source = tmp_path / "mixed-splits.xapk"
    icon = tmp_path / "icon.png"
    base = tmp_path / "com.example.fixture.apk"
    unrelated = tmp_path / "config.arm64_v8a.apk"
    make_apk(base)
    make_apk(
        unrelated,
        MANIFEST.replace(
            'package="com.example.fixture"',
            'package="com.example.unrelated"',
        ).replace("<manifest ", '<manifest split="config.arm64_v8a" '),
    )
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(base, base.name)
        archive.write(unrelated, unrelated.name)
    make_icon(icon)

    report = scan_package(source, icon, profile="quick")

    assert report["status"] == "blocked"
    assert any("内层 APK 包名不一致" in blocker for blocker in report["blockers"])


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


def test_apks_inventory_maps_bundletool_split_names(tmp_path: Path) -> None:
    source = tmp_path / "fixture.apks"
    icon = tmp_path / "icon.png"
    base = tmp_path / "base-master.apk"
    make_apk(base, REQUIRED_SPLIT_MANIFEST)
    split_files = {
        "base-arm64_v8a.apk": "config.arm64_v8a",
        "base-en.apk": "config.en",
        "base-xxhdpi.apk": "config.xxhdpi",
        "feature-master.apk": "feature",
        "feature-arm64_v8a.apk": "feature.config.arm64_v8a",
    }
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("toc.pb", b"synthetic toc")
        archive.write(base, "splits/base-master.apk")
        for file_name, split_name in split_files.items():
            split = tmp_path / file_name
            make_apk(
                split,
                MANIFEST.replace("<manifest ", f'<manifest split="{split_name}" '),
            )
            archive.write(split, f"splits/{file_name}")
        archive.writestr("standalones/standalone-arm64.apk", b"excluded alternative")
    make_icon(icon)

    report = scan_package(source, icon, profile="quick")

    assert report["source"]["format"] == "apks"
    assert report["app"]["packageName"] == "com.example.fixture"
    assert report["xapk"]["bundleFormat"] == "apks"
    assert report["xapk"]["apksMode"] == "split"
    assert report["xapk"]["baseApk"] == "splits/base-master.apk"
    assert {
        row["id"]: row["file"] for row in report["xapk"]["splits"]
    } == {
        "base": "splits/base-master.apk",
        "config.arm64_v8a": "splits/base-arm64_v8a.apk",
        "config.en": "splits/base-en.apk",
        "config.xxhdpi": "splits/base-xxhdpi.apk",
        "feature": "splits/feature-master.apk",
        "feature.config.arm64_v8a": "splits/feature-arm64_v8a.apk",
    }
    assert report["xapk"]["excludedApks"] == [
        "standalones/standalone-arm64.apk"
    ]


def test_apks_universal_archive_is_supported(tmp_path: Path) -> None:
    source = tmp_path / "universal.apks"
    icon = tmp_path / "icon.png"
    universal = tmp_path / "universal.apk"
    make_apk(universal)
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("toc.pb", b"synthetic toc")
        archive.write(universal, "universal.apk")
    make_icon(icon)

    report = scan_package(source, icon, profile="quick")

    assert report["app"]["packageName"] == "com.example.fixture"
    assert report["xapk"]["apksMode"] == "universal"
    assert report["xapk"]["baseApk"] == "universal.apk"
    assert report["xapk"]["splits"][0]["id"] == "base"


def test_sai_apks_archive_and_metadata_are_supported(tmp_path: Path) -> None:
    source = tmp_path / "sai-export.apks"
    icon = tmp_path / "icon.png"
    base = tmp_path / "base.apk"
    arm64 = tmp_path / "split_config.arm64_v8a.apk"
    make_apk(base)
    make_apk(
        arm64,
        MANIFEST.replace("<manifest ", '<manifest split="config.arm64_v8a" '),
    )
    metadata = {
        "meta_version": 2,
        "split_apk": True,
        "label": "SAI Fixture",
        "package": "com.example.fixture",
        "version_code": 241,
        "version_name": "2.4.1",
        "min_sdk": 23,
        "target_sdk": 35,
    }
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("meta.sai_v2.json", json.dumps(metadata))
        archive.write(base, "base.apk")
        archive.write(arm64, arm64.name)
    make_icon(icon)

    report = scan_package(source, icon, profile="quick")

    assert report["app"]["applicationLabel"] == "SAI Fixture"
    assert report["xapk"]["apksContainer"] == "sai"
    assert report["xapk"]["tocPresent"] is False
    assert report["xapk"]["saiMetaFile"] == "meta.sai_v2.json"
    assert [row["id"] for row in report["xapk"]["splits"]] == [
        "base",
        "config.arm64_v8a",
    ]


def test_apks_with_ambiguous_standalones_is_blocked(tmp_path: Path) -> None:
    source = tmp_path / "ambiguous.apks"
    icon = tmp_path / "icon.png"
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("toc.pb", b"synthetic toc")
        archive.writestr("standalones/standalone-arm64.apk", b"arm64")
        archive.writestr("standalones/standalone-x86_64.apk", b"x86")
    make_icon(icon)

    report = scan_package(source, icon, profile="quick")

    assert report["status"] == "blocked"
    assert any("多个 standalone" in blocker for blocker in report["blockers"])


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
    assert not any(
        item["code"] == "manifest.package_missing" for item in report["findings"]
    )


def test_large_resource_archive_warns_but_still_parses_manifest(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "large-resource-game.apk"
    icon = tmp_path / "icon.png"
    make_apk(source)
    with zipfile.ZipFile(source, "a", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("assets/game/imported/resource.stex", b"fixture")
    make_icon(icon)
    monkeypatch.setattr("apkba_analyzer.scanner.MAX_ARCHIVE_ENTRIES_WARNING", 2)

    report = scan_package(source, icon, profile="quick")

    assert report["status"] == "warning"
    assert report["app"]["packageName"] == "com.example.fixture"
    assert any(item["code"] == "archive.many_entries" for item in report["findings"])
    assert not any(
        item["code"] == "archive.too_many_entries" for item in report["findings"]
    )
    assert not any(
        item["code"] == "manifest.package_missing" for item in report["findings"]
    )


def test_extreme_entry_count_remains_blocked_without_secondary_manifest_error(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "entry-flood.apk"
    icon = tmp_path / "icon.png"
    make_apk(source)
    with zipfile.ZipFile(source, "a", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("assets/one", b"fixture")
    make_icon(icon)
    monkeypatch.setattr("apkba_analyzer.scanner.MAX_ARCHIVE_ENTRIES_WARNING", 1)
    monkeypatch.setattr("apkba_analyzer.scanner.MAX_ARCHIVE_ENTRIES_HARD", 2)

    report = scan_package(source, icon, profile="quick")

    assert report["status"] == "blocked"
    assert any(
        item["code"] == "archive.too_many_entries" for item in report["findings"]
    )
    assert not any(
        item["code"] == "manifest.package_missing" for item in report["findings"]
    )
