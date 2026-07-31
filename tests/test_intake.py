from __future__ import annotations

import json
import zipfile
from pathlib import Path

from PIL import Image

from apkba_analyzer.intake import create_intake_bundle
from apkba_analyzer.scanner import scan_package

MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
package="com.example.bundle" android:versionName="1.0" android:versionCode="1">
<uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35" />
<application android:label="Bundle App"><activity android:name=".Main"><intent-filter>
<action android:name="android.intent.action.MAIN"/>
<category android:name="android.intent.category.LAUNCHER"/>
</intent-filter></activity></application></manifest>"""


def test_bundle_is_flat_portable_and_hash_verified(tmp_path: Path) -> None:
    source = tmp_path / "bundle.apk"
    icon = tmp_path / "art.png"
    output = tmp_path / "output"
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
    Image.new("RGB", (512, 512), "#087763").save(icon)
    report = scan_package(source, icon, profile="quick")

    bundle = create_intake_bundle(report, source, icon, output)

    assert (bundle / "bundle.apk").is_file()
    assert (bundle / "icon.png").is_file()
    assert (bundle / "scan_summary.html").is_file()
    handoff = json.loads((bundle / "agent1_handoff.json").read_text(encoding="utf-8"))
    assert handoff["source"]["path"] == "bundle.apk"
    assert handoff["icon"]["path"] == "icon.png"
    assert ":\\" not in json.dumps(handoff)


def test_bundle_copy_uses_detected_source_format_extension(tmp_path: Path) -> None:
    source = tmp_path / "downloaded_pending.apk"
    icon = tmp_path / "art.png"
    output = tmp_path / "output"
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
    Image.new("RGB", (512, 512), "#087763").save(icon)
    report = scan_package(source, icon, profile="quick")
    report["source"]["format"] = "xapk"

    bundle = create_intake_bundle(report, source, icon, output)

    assert (bundle / "downloaded_pending.xapk").is_file()
    handoff = json.loads((bundle / "agent1_handoff.json").read_text(encoding="utf-8"))
    assert handoff["source"]["path"] == "downloaded_pending.xapk"
    assert handoff["source"]["format"] == "xapk"


def test_bundle_copy_preserves_apks_format_extension(tmp_path: Path) -> None:
    source = tmp_path / "downloaded_pending.apk"
    icon = tmp_path / "art.png"
    output = tmp_path / "output"
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
    Image.new("RGB", (512, 512), "#087763").save(icon)
    report = scan_package(source, icon, profile="quick")
    report["source"]["format"] = "apks"

    bundle = create_intake_bundle(report, source, icon, output)

    assert (bundle / "downloaded_pending.apks").is_file()
    handoff = json.loads((bundle / "agent1_handoff.json").read_text(encoding="utf-8"))
    assert handoff["source"]["path"] == "downloaded_pending.apks"
    assert handoff["source"]["format"] == "apks"


def test_optional_developer_text_is_copied_and_recorded(tmp_path: Path) -> None:
    source = tmp_path / "bundle.apk"
    icon = tmp_path / "art.png"
    developer = tmp_path / "developer.txt"
    output = tmp_path / "output"
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
    Image.new("RGB", (512, 512), "#087763").save(icon)
    developer.write_text("SEGA\n", encoding="utf-8")
    report = scan_package(source, icon, profile="quick")

    bundle = create_intake_bundle(
        report,
        source,
        icon,
        output,
        developer_path=developer,
    )

    copied = bundle / "developer.txt"
    handoff = json.loads((bundle / "agent1_handoff.json").read_text(encoding="utf-8"))
    scan_report = json.loads((bundle / "scan_report.json").read_text(encoding="utf-8"))
    assert copied.read_text(encoding="utf-8").strip() == "SEGA"
    assert handoff["developer"]["name"] == "SEGA"
    assert handoff["developer"]["source"] == "operator_provided_text_file"
    assert handoff["developer"]["path"] == "developer.txt"
    assert handoff["developer"]["sha256"]
    assert scan_report["developer"]["name"] == "SEGA"


def test_optional_source_attribution_is_copied_and_recorded(tmp_path: Path) -> None:
    source = tmp_path / "bundle.apk"
    icon = tmp_path / "art.png"
    source_info = tmp_path / "source.txt"
    output = tmp_path / "output"
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
    Image.new("RGB", (512, 512), "#087763").save(icon)
    source_info.write_text("https://example.test/app\n", encoding="utf-8")
    report = scan_package(source, icon, profile="quick")

    bundle = create_intake_bundle(
        report,
        source,
        icon,
        output,
        source_attribution_path=source_info,
    )

    copied = bundle / "source.txt"
    handoff = json.loads((bundle / "agent1_handoff.json").read_text(encoding="utf-8"))
    scan_report = json.loads((bundle / "scan_report.json").read_text(encoding="utf-8"))
    assert copied.read_text(encoding="utf-8").strip() == "https://example.test/app"
    assert handoff["sourceAttribution"]["value"] == "https://example.test/app"
    assert handoff["sourceAttribution"]["source"] == "operator_provided_text_file"
    assert handoff["sourceAttribution"]["path"] == "source.txt"
    assert handoff["sourceAttribution"]["sha256"]
    assert scan_report["sourceAttribution"]["value"] == "https://example.test/app"


def test_bundle_publish_retries_after_transient_permission_error(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "bundle.apk"
    icon = tmp_path / "art.png"
    output = tmp_path / "output"
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
    Image.new("RGB", (512, 512), "#087763").save(icon)
    report = scan_package(source, icon, profile="quick")
    original_replace = Path.replace
    attempts = 0

    def flaky_replace(path: Path, target: Path) -> Path:
        nonlocal attempts
        if path.name.startswith(".apkba-intake-") and attempts == 0:
            attempts += 1
            raise PermissionError(13, "Access is denied", str(target))
        return original_replace(path, target)

    monkeypatch.setattr(Path, "replace", flaky_replace)
    monkeypatch.setattr("apkba_analyzer.intake.time.sleep", lambda _delay: None)

    bundle = create_intake_bundle(report, source, icon, output)

    assert attempts == 1
    assert (bundle / "bundle.apk").is_file()


def test_bundle_publish_chooses_new_name_after_destination_race(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "bundle.apk"
    icon = tmp_path / "art.png"
    output = tmp_path / "output"
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
    Image.new("RGB", (512, 512), "#087763").save(icon)
    report = scan_package(source, icon, profile="quick")
    original_replace = Path.replace
    raced_destination: Path | None = None

    def racing_replace(path: Path, target: Path) -> Path:
        nonlocal raced_destination
        if path.name.startswith(".apkba-intake-") and raced_destination is None:
            raced_destination = Path(target)
            raced_destination.mkdir()
            (raced_destination / "claimed.txt").write_text("other window", encoding="utf-8")
            raise PermissionError(13, "Access is denied", str(target))
        return original_replace(path, target)

    monkeypatch.setattr(Path, "replace", racing_replace)

    bundle = create_intake_bundle(report, source, icon, output)

    assert raced_destination is not None
    assert bundle != raced_destination
    assert (raced_destination / "claimed.txt").is_file()
    assert (bundle / "bundle.apk").is_file()
