from __future__ import annotations

from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from apkba_analyzer.app import DropCard, MainWindow


@pytest.fixture
def qt_app(monkeypatch: pytest.MonkeyPatch) -> QApplication:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    return QApplication.instance() or QApplication([])


def test_drop_card_makes_selected_file_obvious(qt_app: QApplication, tmp_path: Path) -> None:
    source = tmp_path / "Sample App.apk"
    source.write_bytes(b"fixture")
    card = DropCard("APK / XAPK", "拖到这里", {".apk"})
    selected: list[str] = []
    card.path_changed.connect(selected.append)

    card.set_path(str(source))

    assert card.property("selected") is True
    assert card.status_label.text() == "✓ 已添加"
    assert card.file_name_label.text() == source.name
    assert card.path_label.text() == str(source.resolve())
    assert selected == [str(source.resolve())]


def test_copy_handoff_message_puts_ready_text_on_clipboard(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(MainWindow, "_refresh_devices", lambda _self: None)
    window = MainWindow()
    bundle = tmp_path / "agent1-handoff"
    window.bundle_path = str(bundle)

    window._copy_handoff_message()

    assert QApplication.clipboard().text() == (
        "好了。\n"
        f"交接包路径：{bundle}\n"
        "请读取整个交接包，并继续 Agent1 后续流程。"
    )
    assert window.copy_button.text() == "✓ 已复制到剪贴板"
    window.close()
