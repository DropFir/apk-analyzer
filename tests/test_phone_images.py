from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from apkba_analyzer.models import ScanFailure
from apkba_analyzer.phone_images import export_phone_images, list_phone_images


def completed(stdout: str = "", returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class FakeImageAdb:
    def __init__(self, listing: str):
        self.listing = listing
        self.calls: list[list[str]] = []

    def device_facts(self, serial: str):
        return {"serial": serial, "model": "Fixture Phone", "state": "device"}

    def invoke(self, arguments, **_kwargs):
        self.calls.append(arguments)
        if arguments[0] == "shell":
            return completed(self.listing)
        remote, destination = arguments[1:]
        Path(destination).write_bytes(f"copied:{remote}".encode())
        return completed("1 file pulled")


def test_phone_image_listing_filters_extensions_and_sorts_newest_first() -> None:
    listing = (
        "1000.0\0"
        "12\0"
        "/sdcard/DCIM/Camera/old.jpg\0"
        "1200.0\0"
        "20\0"
        "/sdcard/Pictures/new.PNG\0"
        "1300.0\0"
        "30\0"
        "/sdcard/Download/not-an-image.txt\0"
    )
    adb = FakeImageAdb(listing)

    result = list_phone_images("PHONE-1", adb=adb)

    assert result["imageCount"] == 2
    assert [record["file_name"] for record in result["images"]] == [
        "new.PNG",
        "old.jpg",
    ]
    assert result["totalKnownBytes"] == 32
    assert adb.calls[0][0] == "shell"


def test_phone_image_export_preserves_folders_and_avoids_case_collisions(
    tmp_path: Path,
) -> None:
    adb = FakeImageAdb("")
    records = [
        {
            "remote_path": "/sdcard/DCIM/Camera/photo.jpg",
            "size_bytes": 12,
        },
        {
            "remote_path": "/sdcard/DCIM/Camera/PHOTO.JPG",
            "size_bytes": 12,
        },
    ]

    result = export_phone_images("PHONE-1", records, tmp_path, adb=adb)

    exported = Path(result["outputPath"])
    copied = list((exported / "DCIM" / "Camera").iterdir())
    assert result["copiedCount"] == 2
    assert len(copied) == 2
    assert len({path.name.casefold() for path in copied}) == 2
    assert all(path.read_bytes().startswith(b"copied:/sdcard/") for path in copied)


def test_phone_image_export_rejects_paths_outside_shared_storage(
    tmp_path: Path,
) -> None:
    adb = FakeImageAdb("")

    with pytest.raises(ScanFailure, match="共享存储之外"):
        export_phone_images(
            "PHONE-1",
            [{"remote_path": "/data/local/tmp/private.png"}],
            tmp_path,
            adb=adb,
        )
