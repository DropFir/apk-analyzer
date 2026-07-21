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
