from __future__ import annotations

from pathlib import Path

import pytest
from PySide6.QtCore import QMimeData, QPoint, QPointF, Qt, QThread, QUrl
from PySide6.QtGui import QColor, QDragEnterEvent, QDropEvent, QPixmap, QWheelEvent
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from apkba_analyzer.app import DropCard, MainWindow, MediaReviewDialog


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


def test_main_window_uses_landscape_layout(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(MainWindow, "_refresh_devices", lambda _self: None)
    window = MainWindow()

    assert window.width() > window.height()
    assert window.minimumWidth() > window.minimumHeight()
    window.close()


def test_media_review_is_landscape_and_previews_are_clickable(
    qt_app: QApplication, tmp_path: Path
) -> None:
    screenshot = tmp_path / "screenshot.png"
    frame = tmp_path / "frame.png"
    for path, color in ((screenshot, "#087763"), (frame, "#17233b")):
        pixmap = QPixmap(360, 720)
        pixmap.fill(QColor(color))
        assert pixmap.save(str(path))
    review = {
        "applicationLabel": "Fixture",
        "packageName": "com.example.fixture",
        "screenshots": [
            {
                "remote_path": "/sdcard/DCIM/Screenshots/Fixture.png",
                "file_name": "Fixture.png",
                "localPath": str(screenshot),
            }
        ],
        "suggestedScreenshotPaths": ["/sdcard/DCIM/Screenshots/Fixture.png"],
        "selectedRecording": {"file_name": "Fixture.mp4"},
        "localRecordingPath": str(tmp_path / "Fixture.mp4"),
        "recordingFrames": [str(frame)],
        "visibilitySuggestion": "visible",
    }
    dialog = MediaReviewDialog(review, str(tmp_path))

    assert dialog.width() > dialog.height()
    assert len(dialog.media_previews) == 2
    preview = dialog.media_previews[0]
    clicked: list[str] = []
    preview.clicked.disconnect()
    preview.clicked.connect(clicked.append)
    QTest.mouseClick(preview, Qt.MouseButton.LeftButton)

    assert clicked == [str(screenshot)]
    dialog.close()


def test_copy_handoff_message_puts_ready_text_on_clipboard(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(MainWindow, "_refresh_devices", lambda _self: None)
    window = MainWindow()
    bundle = tmp_path / "agent1-handoff"
    window.source_path = "old.apk"
    window.icon_path = "old.webp"
    window.bundle_path = str(bundle)

    window._copy_handoff_message()

    assert QApplication.clipboard().text() == (f"好了。\n交接包：{bundle}")
    assert window.copy_button.text() == "✓ 已复制到剪贴板"
    window.close()


def test_capture_end_result_marks_bundle_ready_for_the_next_apk(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(MainWindow, "_refresh_devices", lambda _self: None)
    window = MainWindow()
    bundle = tmp_path / "agent1-handoff"
    window._on_prepare_success(
        {"app": {"applicationLabel": "Fixture", "packageName": "com.example.fixture"}},
        {
            "deviceModel": "Pixel",
            "deviceSerial": "PHONE-A",
            "launchStatus": "success",
            "focusedActivity": "com.example.fixture/.MainActivity",
            "lowTargetSdkBypassUsed": True,
            "lowTargetSdkBypass": {
                "target_sdk": 22,
                "device_minimum_target_sdk": 24,
            },
        },
        str(bundle),
    )

    assert window.capture_button.isHidden() is False
    assert window._capture_device_serial == "PHONE-A"
    assert "低目标 SDK 兼容安装：已人工确认" in window.detail_label.text()

    window._on_capture_end_success(
        {
            "deviceModel": "Pixel",
            "deviceSerial": "PHONE-A",
            "deviceTime": "2026-07-24T12:00:00+0800",
            "screenshotCount": 3,
            "recordingCount": 1,
        }
    )
    window._copy_handoff_message()

    assert window.capture_button.isEnabled() is False
    assert window.capture_button.text() == "✓ 本次取证边界已记录"
    assert window.source_path == ""
    assert window.icon_path == ""
    assert "截图 3 张，录屏 1 段" in QApplication.clipboard().text()
    assert "可以直接拖入下一份 APK" in window.status_text.text()
    window.close()


def test_full_window_drop_routes_apkm_and_image_together(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(MainWindow, "_refresh_devices", lambda _self: None)
    source = tmp_path / "Sample App.apkm"
    icon = tmp_path / "Sample App.webp"
    source.write_bytes(b"fixture")
    icon.write_bytes(b"fixture")
    window = MainWindow()
    mime_data = QMimeData()
    mime_data.setUrls([QUrl.fromLocalFile(str(icon)), QUrl.fromLocalFile(str(source))])
    enter_event = QDragEnterEvent(
        QPoint(10, 10),
        Qt.DropAction.CopyAction,
        mime_data,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    event = QDropEvent(
        QPointF(10, 10),
        Qt.DropAction.CopyAction,
        mime_data,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )

    QApplication.sendEvent(window.output_edit, enter_event)
    QApplication.sendEvent(window.output_edit, event)

    assert enter_event.isAccepted() is True
    assert event.isAccepted() is True
    assert window.source_path == str(source.resolve())
    assert window.icon_path == str(icon.resolve())
    assert window.source_card.file_name_label.text() == source.name
    assert window.icon_card.file_name_label.text() == icon.name
    window.close()


def test_two_windows_require_and_preserve_independent_device_choices(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(MainWindow, "_refresh_devices", lambda _self: None)
    devices = [
        {"serial": "PHONE-A", "state": "device", "model": "Pixel_A"},
        {"serial": "PHONE-B", "state": "device", "model": "Pixel_B"},
    ]
    first = MainWindow()
    second = MainWindow()

    first._on_devices(devices)
    second._on_devices(devices)

    assert first.device_combo.currentData() is None
    assert second.device_combo.currentData() is None
    first.device_combo.setCurrentIndex(first.device_combo.findData("PHONE-A"))
    second.device_combo.setCurrentIndex(second.device_combo.findData("PHONE-B"))

    first._on_devices(list(reversed(devices)))
    second._on_devices(list(reversed(devices)))

    assert first.device_combo.currentData() == "PHONE-A"
    assert second.device_combo.currentData() == "PHONE-B"
    first.close()
    second.close()


def test_page_scroll_cannot_change_the_selected_device(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(MainWindow, "_refresh_devices", lambda _self: None)
    window = MainWindow()
    window._on_devices(
        [
            {"serial": "PHONE-A", "state": "device", "model": "Pixel_A"},
            {"serial": "PHONE-B", "state": "device", "model": "Pixel_B"},
        ]
    )
    window.device_combo.setCurrentIndex(window.device_combo.findData("PHONE-B"))
    event = QWheelEvent(
        QPointF(10, 10),
        QPointF(10, 10),
        QPoint(0, 0),
        QPoint(0, 120),
        Qt.MouseButton.NoButton,
        Qt.KeyboardModifier.NoModifier,
        Qt.ScrollPhase.ScrollUpdate,
        False,
    )

    QApplication.sendEvent(window.device_combo, event)

    assert window.device_combo.currentData() == "PHONE-B"
    assert event.isAccepted() is False
    window.close()


def test_refresh_never_switches_a_window_to_the_remaining_phone(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(MainWindow, "_refresh_devices", lambda _self: None)
    window = MainWindow()
    window._on_devices(
        [
            {"serial": "PHONE-A", "state": "device", "model": "Pixel_A"},
            {"serial": "PHONE-B", "state": "device", "model": "Pixel_B"},
        ]
    )
    window.device_combo.setCurrentIndex(window.device_combo.findData("PHONE-B"))

    window._on_devices([{"serial": "PHONE-A", "state": "device", "model": "Pixel_A"}])

    assert window.device_combo.currentData() is None
    assert window._selected_device_serial == "PHONE-B"
    assert "PHONE-B" in window.device_combo.currentText()

    window._on_devices(
        [
            {"serial": "PHONE-A", "state": "device", "model": "Pixel_A"},
            {"serial": "PHONE-B", "state": "device", "model": "Pixel_B"},
        ]
    )

    assert window.device_combo.currentData() == "PHONE-B"
    window.close()


def test_two_windows_capture_distinct_serials_when_prepare_starts(
    qt_app: QApplication,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(MainWindow, "_refresh_devices", lambda _self: None)
    monkeypatch.setattr(QThread, "start", lambda _self: None)
    devices = [
        {"serial": "PHONE-A", "state": "device", "model": "Pixel_A"},
        {"serial": "PHONE-B", "state": "device", "model": "Pixel_B"},
    ]
    first = MainWindow()
    second = MainWindow()
    for window, serial in ((first, "PHONE-A"), (second, "PHONE-B")):
        window.source_path = "fixture.apk"
        window.icon_path = "fixture.webp"
        window.output_edit.setText(str(tmp_path))
        window._on_devices(devices)
        window.device_combo.setCurrentIndex(window.device_combo.findData(serial))
        window._start_prepare()

    assert first.worker.serial == "PHONE-A"
    assert second.worker.serial == "PHONE-B"
    assert first.device_combo.isEnabled() is False
    assert second.device_combo.isEnabled() is False
    first.thread = None
    second.thread = None
    first.close()
    second.close()
