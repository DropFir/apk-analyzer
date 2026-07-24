"""PySide6 desktop interface for nontechnical editors."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

from PySide6.QtCore import QEvent, QObject, QSettings, Qt, QThread, QTimer, QUrl, Signal, Slot
from PySide6.QtGui import (
    QCloseEvent,
    QDesktopServices,
    QDragEnterEvent,
    QDragLeaveEvent,
    QDropEvent,
    QWheelEvent,
)
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from apkba_analyzer.device import AdbClient, scan_create_and_prepare
from apkba_analyzer.intake import create_intake_bundle
from apkba_analyzer.scanner import SUPPORTED_IMAGES, SUPPORTED_SOURCES, scan_package


class DropCard(QFrame):
    path_changed = Signal(str)

    def __init__(self, title: str, hint: str, extensions: set[str], parent: QWidget | None = None):
        super().__init__(parent)
        self.extensions = extensions
        self.setAcceptDrops(True)
        self.setObjectName("dropCard")
        self.setProperty("selected", False)
        self.setProperty("dragActive", False)
        self.setMinimumHeight(128)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)

        header = QHBoxLayout()
        self.title = QLabel(title)
        self.title.setObjectName("dropTitle")
        self.status_label = QLabel("等待选择")
        self.status_label.setObjectName("dropStatus")
        header.addWidget(self.title)
        header.addStretch()
        header.addWidget(self.status_label)

        self.hint = QLabel(hint)
        self.hint.setObjectName("dropHint")
        self.hint.setWordWrap(True)
        self.file_name_label = QLabel("")
        self.file_name_label.setObjectName("dropFileName")
        self.file_name_label.setWordWrap(True)
        self.file_name_label.setVisible(False)
        self.path_label = QLabel("")
        self.path_label.setObjectName("pathLabel")
        self.path_label.setWordWrap(True)
        self.path_label.setVisible(False)
        layout.addLayout(header)
        layout.addWidget(self.hint)
        layout.addStretch()
        layout.addWidget(self.file_name_label)
        layout.addWidget(self.path_label)

    def accepts(self, path: Path) -> bool:
        return path.is_file() and path.suffix.lower() in self.extensions

    def set_path(self, path: str) -> None:
        resolved_path = Path(path).resolve()
        resolved = str(resolved_path)
        self._set_visual_state("selected", True)
        self.status_label.setText("✓ 已添加")
        self.file_name_label.setText(resolved_path.name)
        self.file_name_label.setVisible(True)
        self.path_label.setText(resolved)
        self.path_label.setVisible(True)
        self.setToolTip(resolved)
        self.path_label.setToolTip(resolved)
        self.path_changed.emit(resolved)

    def _set_visual_state(self, name: str, value: bool) -> None:
        widgets = (
            self,
            self.title,
            self.status_label,
            self.hint,
            self.file_name_label,
            self.path_label,
        )
        for widget in widgets:
            widget.setProperty(name, value)
            widget.style().unpolish(widget)
            widget.style().polish(widget)
            widget.update()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        paths = [Path(url.toLocalFile()) for url in event.mimeData().urls() if url.isLocalFile()]
        if any(self.accepts(path) for path in paths):
            self._set_visual_state("dragActive", True)
            event.acceptProposedAction()

    def dragLeaveEvent(self, event: QDragLeaveEvent) -> None:  # noqa: N802
        self._set_visual_state("dragActive", False)
        event.accept()

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        self._set_visual_state("dragActive", False)
        for url in event.mimeData().urls():
            path = Path(url.toLocalFile())
            if self.accepts(path):
                self.set_path(str(path))
                event.acceptProposedAction()
                return


class DeviceComboBox(QComboBox):
    """Require an explicit click before wheel input can change the device."""

    def wheelEvent(self, event: QWheelEvent) -> None:  # noqa: N802
        if self.view().isVisible():
            super().wheelEvent(event)
            return
        event.ignore()


class ScanWorker(QObject):
    progress = Signal(int, str)
    succeeded = Signal(object, str)
    failed = Signal(str, str)

    def __init__(self, source: str, icon: str, output: str):
        super().__init__()
        self.source = source
        self.icon = icon
        self.output = output

    @Slot()
    def run(self) -> None:
        try:
            report = scan_package(
                self.source,
                self.icon,
                profile="standard",
                progress=lambda value, message: self.progress.emit(value, message),
            )
            bundle = ""
            if report["status"] != "blocked":
                self.progress.emit(96, "复制原件并生成 Agent1 交接包…")
                bundle = str(create_intake_bundle(report, self.source, self.icon, self.output))
            self.succeeded.emit(report, bundle)
        except Exception as error:
            self.failed.emit(str(error), traceback.format_exc())


class DeviceWorker(QObject):
    succeeded = Signal(object)
    failed = Signal(str, str)

    @Slot()
    def run(self) -> None:
        try:
            self.succeeded.emit(AdbClient().list_devices())
        except Exception as error:
            self.failed.emit(str(error), traceback.format_exc())


class PrepareWorker(QObject):
    progress = Signal(int, str)
    succeeded = Signal(object, object, str)
    failed = Signal(str, str)

    def __init__(self, source: str, icon: str, output: str, serial: str):
        super().__init__()
        self.source = source
        self.icon = icon
        self.output = output
        self.serial = serial

    @Slot()
    def run(self) -> None:
        try:
            report, bundle, result = scan_create_and_prepare(
                self.source,
                self.icon,
                self.output,
                self.serial,
                progress=lambda value, message: self.progress.emit(value, message),
            )
            self.succeeded.emit(report, result, str(bundle))
        except Exception as error:
            self.failed.emit(str(error), traceback.format_exc())


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.source_path = ""
        self.icon_path = ""
        self.bundle_path = ""
        self._selected_device_serial: str | None = None
        self._active_device_serial: str | None = None
        self._active_device_display = ""
        self.thread: QThread | None = None
        self.worker: QObject | None = None
        self.copy_reset_timer = QTimer(self)
        self.copy_reset_timer.setSingleShot(True)
        self.copy_reset_timer.timeout.connect(self._reset_copy_button)
        self.settings = QSettings("APKBA", "APKBA Analyzer")
        self.setWindowTitle("APKBA Analyzer")
        self.setAcceptDrops(True)
        self.resize(840, 540)
        self.setMinimumSize(700, 480)
        self._build_ui()
        self._apply_styles()

    def _build_ui(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        root = QWidget()
        scroll.setWidget(root)
        self.setCentralWidget(scroll)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(24, 18, 24, 22)
        layout.setSpacing(12)

        cards = QGridLayout()
        cards.setHorizontalSpacing(12)
        cards.setVerticalSpacing(8)
        self.source_card = DropCard(
            "① APK / XAPK / APKM",
            "拖拽或选择安装包",
            SUPPORTED_SOURCES,
        )
        self.icon_card = DropCard(
            "② 应用图标",
            "PNG / JPG / WebP / AVIF · 正方形",
            SUPPORTED_IMAGES,
        )
        cards.addWidget(self.source_card, 0, 0)
        cards.addWidget(self.icon_card, 0, 1)
        choose_source = QPushButton("选择安装包")
        choose_icon = QPushButton("选择图标")
        choose_source.clicked.connect(self._choose_source)
        choose_icon.clicked.connect(self._choose_icon)
        cards.addWidget(choose_source, 1, 0)
        cards.addWidget(choose_icon, 1, 1)
        layout.addLayout(cards)

        output_frame = QFrame()
        output_frame.setObjectName("panel")
        output_layout = QHBoxLayout(output_frame)
        output_layout.setContentsMargins(14, 10, 14, 10)
        output_label = QLabel("输出位置")
        output_label.setObjectName("fieldLabel")
        self.output_edit = QLineEdit(str(self.settings.value("output", Path.home() / "Desktop")))
        self.output_edit.setPlaceholderText("交接包保存位置")
        choose_output = QPushButton("浏览…")
        choose_output.clicked.connect(self._choose_output)
        output_layout.addWidget(output_label)
        output_layout.addWidget(self.output_edit, 1)
        output_layout.addWidget(choose_output)
        layout.addWidget(output_frame)

        device_frame = QFrame()
        device_frame.setObjectName("panel")
        device_layout = QHBoxLayout(device_frame)
        device_layout.setContentsMargins(14, 10, 14, 10)
        device_label = QLabel("本窗口手机")
        device_label.setObjectName("fieldLabel")
        self.device_combo = DeviceComboBox()
        self.device_combo.addItem("正在检查 USB 调试设备…", None)
        self.device_combo.setMinimumWidth(260)
        self.device_combo.setToolTip("每个窗口单独选择并绑定一台手机")
        self.device_combo.currentIndexChanged.connect(self._on_device_selection_changed)
        self.refresh_button = QPushButton("刷新")
        self.refresh_button.clicked.connect(self._refresh_devices)
        device_layout.addWidget(device_label)
        device_layout.addWidget(self.device_combo, 1)
        device_layout.addWidget(self.refresh_button)
        layout.addWidget(device_frame)

        action_row = QHBoxLayout()
        self.scan_button = QPushButton("扫描并生成交接包")
        self.scan_button.setMinimumHeight(42)
        self.scan_button.clicked.connect(self._start_scan)
        self.prepare_button = QPushButton("连接手机取证")
        self.prepare_button.setObjectName("primaryButton")
        self.prepare_button.setMinimumHeight(42)
        self.prepare_button.clicked.connect(self._start_prepare)
        action_row.addStretch()
        action_row.addWidget(self.scan_button)
        action_row.addWidget(self.prepare_button)
        layout.addLayout(action_row)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        layout.addWidget(self.progress)

        self.result_panel = QFrame()
        self.result_panel.setObjectName("resultPanel")
        result_layout = QVBoxLayout(self.result_panel)
        result_layout.setContentsMargins(16, 12, 16, 14)
        result_top = QHBoxLayout()
        self.status_badge = QLabel("等待文件")
        self.status_badge.setObjectName("statusBadge")
        self.status_text = QLabel("请选择安装包和图标。")
        self.status_text.setObjectName("statusText")
        result_top.addWidget(self.status_badge)
        result_top.addWidget(self.status_text, 1)
        result_layout.addLayout(result_top)
        self.detail_label = QLabel("")
        self.detail_label.setObjectName("details")
        self.detail_label.setWordWrap(True)
        self.detail_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        result_layout.addWidget(self.detail_label)
        self.open_button = QPushButton("打开交接包")
        self.open_button.setVisible(False)
        self.open_button.clicked.connect(self._open_bundle)
        self.copy_button = QPushButton("复制交接文案")
        self.copy_button.setObjectName("copyButton")
        self.copy_button.setVisible(False)
        self.copy_button.clicked.connect(self._copy_handoff_message)
        result_actions = QHBoxLayout()
        result_actions.addWidget(self.open_button)
        result_actions.addWidget(self.copy_button)
        result_actions.addStretch()
        result_layout.addLayout(result_actions)
        layout.addWidget(self.result_panel)
        layout.addStretch()

        self.source_card.path_changed.connect(self._set_source)
        self.icon_card.path_changed.connect(self._set_icon)
        for drop_target in (
            scroll.viewport(),
            root,
            self.source_card,
            self.icon_card,
            self.output_edit,
            self.device_combo,
        ):
            drop_target.setAcceptDrops(True)
            drop_target.installEventFilter(self)
        QTimer.singleShot(0, self._refresh_devices)

    def _apply_styles(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow, QScrollArea, QWidget { background: #f5f7fb; color: #17233b; }
            QLabel { background: transparent; }
            QFrame#dropCard {
                background: white; border: 2px dashed #c8d4e5; border-radius: 14px;
            }
            QFrame#dropCard:hover { border-color: #15a487; background: #fbfffd; }
            QFrame#dropCard[dragActive="true"] {
                background: #edfff9; border: 3px dashed #12a181;
            }
            QFrame#dropCard[selected="true"] {
                background: #f0fbf7; border: 3px solid #0d9275;
            }
            QLabel#dropTitle { font-size: 17px; font-weight: 700; }
            QLabel#dropTitle[selected="true"] { color: #076b57; }
            QLabel#dropStatus {
                color: #64748b; background: #eef2f7; border-radius: 10px;
                padding: 4px 10px; font-size: 12px; font-weight: 700;
            }
            QLabel#dropStatus[selected="true"] { color: white; background: #0d9275; }
            QLabel#dropHint, QLabel#pathLabel { color: #64748b; }
            QLabel#dropFileName { color: #42536b; font-size: 14px; font-weight: 700; }
            QLabel#dropFileName[selected="true"] { color: #075f4e; font-size: 15px; }
            QLabel#pathLabel { font-size: 12px; }
            QFrame#panel, QFrame#resultPanel {
                background: white; border: 1px solid #dfe6ef; border-radius: 12px;
            }
            QLabel#fieldLabel { font-weight: 700; }
            QLineEdit {
                background: #f8fafc; border: 1px solid #d8e1ec;
                border-radius: 8px; padding: 9px;
            }
            QComboBox {
                background: #f8fafc; border: 1px solid #d8e1ec;
                border-radius: 8px; padding: 9px;
            }
            QPushButton {
                background: white; border: 1px solid #cbd6e5;
                border-radius: 8px; padding: 9px 15px; font-weight: 650;
            }
            QPushButton:hover { border-color: #159b82; color: #087763; }
            QPushButton#primaryButton {
                background: #087763; color: white; border: 0; padding: 11px 24px;
            }
            QPushButton#primaryButton:hover { background: #066653; }
            QPushButton#primaryButton:disabled { background: #93a7a1; }
            QPushButton#copyButton {
                background: #e5f7f1; color: #087763; border-color: #8bcfbd;
            }
            QPushButton#copyButton:hover { background: #d7f2e9; border-color: #0d9275; }
            QProgressBar { border: 0; background: #e4eaf2; border-radius: 4px; height: 8px; }
            QProgressBar::chunk { background: #17a88a; border-radius: 4px; }
            QLabel#statusBadge {
                background: #e9eef5; color: #41526b; border-radius: 10px;
                padding: 5px 10px; font-weight: 750;
            }
            QLabel#statusText { font-weight: 650; }
            QLabel#details { color: #58677d; line-height: 1.5; }
            """
        )

    @Slot(str)
    def _set_source(self, path: str) -> None:
        self.source_path = path
        self._update_file_selection_status()

    @Slot(str)
    def _set_icon(self, path: str) -> None:
        self.icon_path = path
        self._update_file_selection_status()

    def _update_file_selection_status(self) -> None:
        if self.source_path and self.icon_path:
            self.status_badge.setText("文件已就绪")
            self.status_badge.setStyleSheet("background:#ddf7ee;color:#087763")
            self.status_text.setText("安装包和图标均已添加，可以开始扫描。")
        elif self.source_path:
            self.status_badge.setText("已选择 1/2")
            self.status_badge.setStyleSheet("background:#fff2cf;color:#7d5800")
            self.status_text.setText("安装包已添加，再选择一个应用图标。")
        elif self.icon_path:
            self.status_badge.setText("已选择 1/2")
            self.status_badge.setStyleSheet("background:#fff2cf;color:#7d5800")
            self.status_text.setText("图标已添加，再选择一个 APK/XAPK/APKM。")

    def _choose_source(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "选择 APK/XAPK/APKM",
            "",
            "Android package (*.apk *.xapk *.apkm)",
        )
        if path:
            self.source_card.set_path(path)

    def _choose_icon(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择应用图标", "", "Images (*.png *.jpg *.jpeg *.webp *.avif)"
        )
        if path:
            self.icon_card.set_path(path)

    def _choose_output(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "选择输出位置", self.output_edit.text())
        if path:
            self.output_edit.setText(path)

    def _start_scan(self) -> None:
        output = self.output_edit.text().strip()
        if not self.source_path or not self.icon_path or not output:
            QMessageBox.information(self, "还差一步", "请选择 APK/XAPK/APKM、图标和输出位置。")
            return
        self.settings.setValue("output", output)
        self._active_device_serial = None
        self._active_device_display = ""
        self._set_busy(True)
        self.open_button.setVisible(False)
        self.copy_button.setVisible(False)
        self.bundle_path = ""
        self.progress.setValue(1)
        self.status_badge.setText("扫描中")
        self.status_badge.setStyleSheet("background:#e9eef5;color:#41526b")
        self.status_text.setText("正在检查输入文件…")
        self.detail_label.clear()
        self.thread = QThread(self)
        self.worker = ScanWorker(self.source_path, self.icon_path, output)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._on_progress)
        self.worker.succeeded.connect(self._on_success)
        self.worker.failed.connect(self._on_failure)
        self.worker.succeeded.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self._thread_finished)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def _start_prepare(self) -> None:
        output = self.output_edit.text().strip()
        serial = self.device_combo.currentData()
        if not self.source_path or not self.icon_path or not output:
            QMessageBox.information(self, "还差一步", "请选择 APK/XAPK/APKM、图标和输出位置。")
            return
        if not serial:
            QMessageBox.information(
                self,
                "请选择手机",
                "请连接手机、开启 USB 调试并授权，然后刷新并选择状态为“已授权”的设备。",
            )
            return
        self._active_device_serial = str(serial)
        self._active_device_display = self.device_combo.currentText()
        self.settings.setValue("output", output)
        self._set_busy(True)
        self.open_button.setVisible(False)
        self.copy_button.setVisible(False)
        self.bundle_path = ""
        self.progress.setValue(1)
        self.status_badge.setText("准备中")
        self.status_badge.setStyleSheet("background:#e9eef5;color:#41526b")
        self.status_text.setText(f"目标已锁定：{self._active_device_display}；正在静态扫描…")
        self.detail_label.clear()
        self.thread = QThread(self)
        self.worker = PrepareWorker(
            self.source_path,
            self.icon_path,
            output,
            str(serial),
        )
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._on_progress)
        self.worker.succeeded.connect(self._on_prepare_success)
        self.worker.failed.connect(self._on_failure)
        self.worker.succeeded.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self._thread_finished)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def _refresh_devices(self) -> None:
        if self.thread and self.thread.isRunning():
            return
        current_serial = self.device_combo.currentData()
        if current_serial:
            self._selected_device_serial = str(current_serial)
        signals_were_blocked = self.device_combo.blockSignals(True)
        try:
            self.device_combo.clear()
            self.device_combo.addItem("正在检查 USB 调试设备…", None)
        finally:
            self.device_combo.blockSignals(signals_were_blocked)
        self.device_combo.setEnabled(False)
        self.refresh_button.setEnabled(False)
        self.thread = QThread(self)
        self.worker = DeviceWorker()
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.succeeded.connect(self._on_devices)
        self.worker.failed.connect(self._on_device_failure)
        self.worker.succeeded.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self._thread_finished)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    @Slot(object)
    def _on_devices(self, devices: object) -> None:
        self.refresh_button.setEnabled(True)
        self.device_combo.setEnabled(True)
        rows = list(devices)
        online_serials = [
            str(row.get("serial") or "")
            for row in rows
            if row.get("state") == "device" and row.get("serial")
        ]
        remembered_serial = self._selected_device_serial
        signals_were_blocked = self.device_combo.blockSignals(True)
        try:
            self.device_combo.clear()
            for row in rows:
                serial = str(row.get("serial") or "")
                state = row.get("state", "")
                model = str(row.get("model") or row.get("device") or "Android 设备").replace(
                    "_", " "
                )
                if state == "device":
                    self.device_combo.addItem(f"{model} · 已授权 · {serial}", serial)
                else:
                    state_text = "等待手机授权" if state == "unauthorized" else state
                    self.device_combo.addItem(f"{model} · {state_text} · {serial}", None)

            if not rows:
                self.device_combo.addItem("未发现设备：请连接数据线并开启 USB 调试", None)
            elif not online_serials:
                self.device_combo.insertItem(0, "没有已授权设备，请查看手机弹窗", None)
            elif len(online_serials) > 1:
                self.device_combo.insertItem(
                    0,
                    f"请选择本窗口使用的手机（{len(online_serials)} 台已授权）",
                    None,
                )

            remembered_index = (
                self.device_combo.findData(remembered_serial) if remembered_serial else -1
            )
            if remembered_index >= 0:
                self.device_combo.setCurrentIndex(remembered_index)
            elif remembered_serial:
                self.device_combo.insertItem(
                    0,
                    f"原绑定手机已断开 · {remembered_serial}",
                    None,
                )
                self.device_combo.setCurrentIndex(0)
            elif len(online_serials) == 1:
                self.device_combo.setCurrentIndex(self.device_combo.findData(online_serials[0]))
            else:
                self.device_combo.setCurrentIndex(0)
        finally:
            self.device_combo.blockSignals(signals_were_blocked)

        selected_serial = self.device_combo.currentData()
        if selected_serial:
            self._selected_device_serial = str(selected_serial)
        self._update_device_tooltip()

    @Slot(str, str)
    def _on_device_failure(self, message: str, _detail: str) -> None:
        self.refresh_button.setEnabled(True)
        self.device_combo.setEnabled(True)
        signals_were_blocked = self.device_combo.blockSignals(True)
        try:
            self.device_combo.clear()
            suffix = (
                f"；原绑定 {self._selected_device_serial}" if self._selected_device_serial else ""
            )
            self.device_combo.addItem(f"ADB 不可用：{message}{suffix}", None)
        finally:
            self.device_combo.blockSignals(signals_were_blocked)
        self._update_device_tooltip()

    @Slot(int)
    def _on_device_selection_changed(self, _index: int) -> None:
        serial = self.device_combo.currentData()
        if serial:
            self._selected_device_serial = str(serial)
        self._update_device_tooltip()

    def _update_device_tooltip(self) -> None:
        serial = self.device_combo.currentData()
        if serial:
            message = f"本窗口已绑定到设备序列号：{serial}"
        elif self._selected_device_serial:
            message = (
                f"原绑定设备 {self._selected_device_serial} 当前不可用；不会自动切换到其他手机"
            )
        else:
            message = "每个窗口必须单独选择一台手机"
        self.device_combo.setToolTip(message)
        self.prepare_button.setToolTip(message)

    @Slot(int, str)
    def _on_progress(self, value: int, message: str) -> None:
        self.progress.setValue(value)
        if self._active_device_serial:
            self.status_text.setText(f"{message} ｜ 目标：{self._active_device_display}")
        else:
            self.status_text.setText(message)

    @Slot(object, str)
    def _on_success(self, report: object, bundle: str) -> None:
        self._set_busy(False)
        result = dict(report)
        status = result.get("status")
        app = result.get("app") or {}
        signature = result.get("signature") or {}
        if status == "blocked":
            self.status_badge.setText("需要处理")
            self.status_badge.setStyleSheet("background:#fee8e7;color:#a52a24")
            self.status_text.setText("扫描发现阻塞项，未生成交接包。")
        elif status == "warning":
            self.status_badge.setText("已生成 · 有提醒")
            self.status_badge.setStyleSheet("background:#fff2cf;color:#7d5800")
            self.status_text.setText("交接包已生成，请查看提醒。")
        else:
            self.status_badge.setText("通过")
            self.status_badge.setStyleSheet("background:#ddf7ee;color:#087763")
            self.status_text.setText("扫描通过，Agent1 交接包已生成。")
        findings = result.get("findings") or []
        finding_text = (
            "\n".join(f"• {item.get('message')}" for item in findings) or "• 没有发现阻塞项或警告"
        )
        certificate = ", ".join(signature.get("certificateSha256") or []) or "未确认"
        self.detail_label.setText(
            f"应用：{app.get('applicationLabel') or '未确认'}\n"
            f"包名：{app.get('packageName') or '未确认'}\n"
            f"版本：{app.get('versionName') or '未确认'} ({app.get('versionCode') or '未确认'})\n"
            f"签名证书 SHA-256：{certificate}\n\n{finding_text}"
        )
        self.bundle_path = bundle
        self.open_button.setVisible(bool(bundle))
        self.copy_button.setVisible(bool(bundle))

    @Slot(object, object, str)
    def _on_prepare_success(self, report: object, result: object, bundle: str) -> None:
        self._set_busy(False)
        scan_result = dict(report)
        prepare_result = dict(result)
        app = scan_result.get("app") or {}
        signature = scan_result.get("signature") or {}
        self.status_badge.setText("等待人工取证")
        self.status_badge.setStyleSheet("background:#ddf7ee;color:#087763")
        self.status_text.setText("安装和启动准备已完成。现在请在手机上手动截图和录屏。")
        certificate = ", ".join(signature.get("certificateSha256") or []) or "未确认"
        self.detail_label.setText(
            f"应用：{app.get('applicationLabel') or '未确认'}\n"
            f"包名：{app.get('packageName') or '未确认'}\n"
            f"手机：{prepare_result.get('deviceModel') or '未确认'}"
            f" · {prepare_result.get('deviceSerial') or '序列号未确认'}\n"
            f"启动结果：{prepare_result.get('launchStatus') or '未确认'}\n"
            f"前台页面：{prepare_result.get('focusedActivity') or '未确认'}\n"
            f"签名证书 SHA-256：{certificate}\n\n"
            "下一步：在手机上手动完成应用 UI 截图和一段录屏。\n"
            "完成后把整个交接文件夹交给 Agent1，并回复“好了”；"
            "如果截图或录屏黑屏/被禁止，请在“好了”后明确写出来。"
        )
        self.bundle_path = bundle
        self.open_button.setVisible(True)
        self.copy_button.setVisible(True)

    @Slot(str, str)
    def _on_failure(self, message: str, detail: str) -> None:
        self._set_busy(False)
        self.status_badge.setText("失败")
        self.status_badge.setStyleSheet("background:#fee8e7;color:#a52a24")
        self.status_text.setText(message)
        target = (
            f"目标手机：{self._active_device_display}\n\n" if self._active_device_serial else ""
        )
        self.detail_label.setText(target + detail)

    def _set_busy(self, busy: bool) -> None:
        self.scan_button.setEnabled(not busy)
        self.prepare_button.setEnabled(not busy)
        self.refresh_button.setEnabled(not busy)
        self.device_combo.setEnabled(not busy)

    @Slot()
    def _thread_finished(self) -> None:
        self.worker = None
        self.thread = None
        self._active_device_serial = None
        self._active_device_display = ""

    def _open_bundle(self) -> None:
        if self.bundle_path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(self.bundle_path))

    @staticmethod
    def _local_drop_paths(event: QDragEnterEvent | QDropEvent) -> list[Path]:
        return [Path(url.toLocalFile()) for url in event.mimeData().urls() if url.isLocalFile()]

    def _set_drop_highlights(self, paths: list[Path]) -> bool:
        source_ready = any(
            path.is_file() and path.suffix.lower() in SUPPORTED_SOURCES for path in paths
        )
        icon_ready = any(
            path.is_file() and path.suffix.lower() in SUPPORTED_IMAGES for path in paths
        )
        self.source_card._set_visual_state("dragActive", source_ready)
        self.icon_card._set_visual_state("dragActive", icon_ready)
        return source_ready or icon_ready

    def _clear_drop_highlights(self) -> None:
        self.source_card._set_visual_state("dragActive", False)
        self.icon_card._set_visual_state("dragActive", False)

    def _route_dropped_paths(self, paths: list[Path]) -> bool:
        source = next(
            (path for path in paths if path.is_file() and path.suffix.lower() in SUPPORTED_SOURCES),
            None,
        )
        icon = next(
            (path for path in paths if path.is_file() and path.suffix.lower() in SUPPORTED_IMAGES),
            None,
        )
        if source:
            self.source_card.set_path(str(source))
        if icon:
            self.icon_card.set_path(str(icon))
        return source is not None or icon is not None

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:  # noqa: N802
        if event.type() in {QEvent.Type.DragEnter, QEvent.Type.DragMove}:
            paths = self._local_drop_paths(event)
            if self._set_drop_highlights(paths):
                event.acceptProposedAction()
            else:
                event.ignore()
            return True
        if event.type() == QEvent.Type.DragLeave:
            self._clear_drop_highlights()
            event.accept()
            return True
        if event.type() == QEvent.Type.Drop:
            paths = self._local_drop_paths(event)
            self._clear_drop_highlights()
            if self._route_dropped_paths(paths):
                event.acceptProposedAction()
            else:
                event.ignore()
            return True
        return super().eventFilter(watched, event)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        if self._set_drop_highlights(self._local_drop_paths(event)):
            event.acceptProposedAction()

    def dragLeaveEvent(self, event: QDragLeaveEvent) -> None:  # noqa: N802
        self._clear_drop_highlights()
        event.accept()

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        paths = self._local_drop_paths(event)
        self._clear_drop_highlights()
        if self._route_dropped_paths(paths):
            event.acceptProposedAction()

    def _copy_handoff_message(self) -> None:
        if not self.bundle_path:
            return
        message = f"好了。\n交接包：{self.bundle_path}"
        QApplication.clipboard().setText(message)
        self.copy_button.setText("✓ 已复制到剪贴板")
        self.copy_reset_timer.start(2200)

    def _reset_copy_button(self) -> None:
        self.copy_button.setText("复制交接文案")

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        if self.thread and self.thread.isRunning():
            QMessageBox.information(self, "扫描仍在进行", "请等待当前扫描完成后再关闭工具。")
            event.ignore()
            return
        event.accept()


def run() -> int:
    application = QApplication.instance() or QApplication(sys.argv)
    application.setApplicationName("APKBA Analyzer")
    application.setOrganizationName("APKBA")
    window = MainWindow()
    window.show()
    return application.exec()
