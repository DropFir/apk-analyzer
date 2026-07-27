from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from apkba_analyzer.input_bundle import import_input_container
from apkba_analyzer.models import ScanFailure


def test_wrapper_zip_imports_required_and_optional_inputs(tmp_path: Path) -> None:
    wrapper = tmp_path / "editor-inputs.zip"
    with zipfile.ZipFile(wrapper, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("nested/example.xapk", b"xapk fixture")
        archive.writestr("nested/icon.webp", b"webp fixture")
        archive.writestr("nested/developer.txt", "Dexcom\n")
        archive.writestr("nested/source.txt", "https://example.test/app\n")

    imported = import_input_container(wrapper)
    extraction_root = imported.source.parent

    assert imported.source.name == "example.xapk"
    assert imported.icon.name == "icon.webp"
    assert imported.developer is not None
    assert imported.developer.read_text(encoding="utf-8") == "Dexcom\n"
    assert imported.source_info is not None
    assert imported.source_info.read_text(encoding="utf-8").startswith("https://")
    assert wrapper.is_file()

    imported.cleanup()
    assert not extraction_root.exists()
    assert wrapper.is_file()


def test_folder_import_allows_both_optional_text_files_to_be_absent(
    tmp_path: Path,
) -> None:
    folder = tmp_path / "inputs"
    folder.mkdir()
    source = folder / "example.apk"
    icon = folder / "icon.png"
    source.write_bytes(b"apk fixture")
    icon.write_bytes(b"png fixture")

    imported = import_input_container(folder)

    assert imported.source == source
    assert imported.icon == icon
    assert imported.developer is None
    assert imported.source_info is None


def test_folder_import_accepts_resource_and_develop_aliases(tmp_path: Path) -> None:
    folder = tmp_path / "inputs"
    folder.mkdir()
    (folder / "example.apkm").write_bytes(b"apkm fixture")
    (folder / "icon.avif").write_bytes(b"avif fixture")
    (folder / "develop.txt").write_text("Publisher\n", encoding="utf-8")
    (folder / "resource.txt").write_text("Downloaded by editor\n", encoding="utf-8")

    imported = import_input_container(folder)

    assert imported.developer is not None
    assert imported.developer.name == "develop.txt"
    assert imported.source_info is not None
    assert imported.source_info.name == "resource.txt"


def test_wrapper_zip_accepts_apks_as_the_install_source(tmp_path: Path) -> None:
    wrapper = tmp_path / "apks-input.zip"
    with zipfile.ZipFile(wrapper, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("input/example.apks", b"apks fixture")
        archive.writestr("input/icon.png", b"icon fixture")

    imported = import_input_container(wrapper)

    assert imported.source.name == "example.apks"
    assert imported.icon.name == "icon.png"
    imported.cleanup()


def test_wrapper_zip_rejects_ambiguous_packages_and_unsafe_paths(
    tmp_path: Path,
) -> None:
    ambiguous = tmp_path / "ambiguous.zip"
    with zipfile.ZipFile(ambiguous, "w") as archive:
        archive.writestr("one.apk", b"one")
        archive.writestr("two.xapk", b"two")
        archive.writestr("icon.png", b"icon")

    with pytest.raises(ScanFailure, match="多个APK/XAPK/APKM/APKS"):
        import_input_container(ambiguous)

    unsafe = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(unsafe, "w") as archive:
        archive.writestr("example.apk", b"one")
        archive.writestr("icon.png", b"icon")
        archive.writestr("../escape.txt", b"unsafe")

    with pytest.raises(ScanFailure, match="不安全路径"):
        import_input_container(unsafe)
