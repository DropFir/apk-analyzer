"""PySide6 desktop interface for nontechnical editors."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

from PySide6.QtCore import QObject, QSettings, Qt, QThread, QTimer, QUrl, Signal, Slot
from PySide6.QtGui import (
    QCloseEvent,
    QDesktopServices,
    QDragEnterEvent,
    QDragLeaveEvent,
    QDropEvent,
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
        self.setMinimumHeight(156)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 18)

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
        self.file_name_label = QLabel("尚未添加文件")
        self.file_name_label.setObjectName("dropFileName")
        self.file_name_label.setWordWrap(True)
        self.path_label = QLabel("拖拽成功后会在这里显示文件名")
        self.path_label.setObjectName("pathLabel")
        self.path_label.setWordWrap(True)
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
        self.path_label.setText(resolved)
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
        self.thread: QThread | None = None
        self.worker: QObject | None = None
        self.settings = QSettings("APKBA", "APKBA Analyzer")
        self.setWindowTitle("APKBA Analyzer")
        self.resize(1080, 760)
        self.setMinimumSize(860, 640)
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
        layout.setContentsMargins(42, 34, 42, 40)
        layout.setSpacing(20)

        eyebrow = QLabel("APKBA · AGENT1 INTAKE")
        eyebrow.setObjectName("eyebrow")
        title = QLabel("把安装包交给工具，剩下的交给 Agent1")
        title.setObjectName("heroTitle")
        subtitle = QLabel(
            "拖入一个 APK/XAPK 和一个图标。工具会在本机完成完整性、manifest、split 与签名检查，"
            "然后生成可直接交给 Agent1 的文件夹。不会上传文件。"
        )
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(eyebrow)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        cards = QGridLayout()
        cards.setHorizontalSpacing(18)
        self.source_card = DropCard(
            "① APK / XAPK",
            "拖到这里，或点击下方按钮选择安装包",
            SUPPORTED_SOURCES,
        )
        self.icon_card = DropCard(
            "② 应用图标",
            "支持 PNG、JPG、WebP、AVIF；必须为正方形",
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
        output_layout.setContentsMargins(20, 16, 20, 16)
        output_label = QLabel("输出位置")
        output_label.setObjectName("fieldLabel")
        self.output_edit = QLineEdit(str(self.settings.value("output", Path.home() / "Desktop")))
        self.output_edit.setPlaceholderText("选择保存 Agent1 交接包的位置")
        choose_output = QPushButton("浏览…")
        choose_output.clicked.connect(self._choose_output)
        output_layout.addWidget(output_label)
        output_layout.addWidget(self.output_edit, 1)
        output_layout.addWidget(choose_output)
        layout.addWidget(output_frame)

        device_frame = QFrame()
        device_frame.setObjectName("panel")
        device_layout = QHBoxLayout(device_frame)
        device_layout.setContentsMargins(20, 16, 20, 16)
        device_label = QLabel("取证手机")
        device_label.setObjectName("fieldLabel")
        self.device_combo = QComboBox()
        self.device_combo.addItem("正在检查 USB 调试设备…", None)
        self.device_combo.setMinimumWidth(360)
        self.refresh_button = QPushButton("刷新设备")
        self.refresh_button.clicked.connect(self._refresh_devices)
        device_layout.addWidget(device_label)
        device_layout.addWidget(self.device_combo, 1)
        device_layout.addWidget(self.refresh_button)
        layout.addWidget(device_frame)

        action_row = QHBoxLayout()
        trust = QLabel("● 静态扫描不联网 · 取证模式只操作明确选择的手机")
        trust.setObjectName("trust")
        self.scan_button = QPushButton("开始扫描并生成交接包")
        self.scan_button.setMinimumHeight(48)
        self.scan_button.clicked.connect(self._start_scan)
        self.prepare_button = QPushButton("连接手机并开始取证")
        self.prepare_button.setObjectName("primaryButton")
        self.prepare_button.setMinimumHeight(48)
        self.prepare_button.clicked.connect(self._start_prepare)
        action_row.addWidget(trust)
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
        result_layout.setContentsMargins(22, 18, 22, 20)
        result_top = QHBoxLayout()
        self.status_badge = QLabel("等待文件")
        self.status_badge.setObjectName("statusBadge")
        self.status_text = QLabel("选择两个文件后即可开始。")
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
        result_layout.addWidget(self.open_button, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.result_panel)
        layout.addStretch()

        self.source_card.path_changed.connect(self._set_source)
        self.icon_card.path_changed.connect(self._set_icon)
        QTimer.singleShot(0, self._refresh_devices)

    def _apply_styles(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow, QScrollArea, QWidget { background: #f5f7fb; color: #17233b; }
            QLabel { background: transparent; }
            QLabel#eyebrow {
                color: #087763; font-size: 12px; font-weight: 800; letter-spacing: 1px;
            }
            QLabel#heroTitle { font-size: 29px; font-weight: 750; }
            QLabel#subtitle { color: #5a6980; font-size: 15px; max-width: 880px; }
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
            QLabel#trust { color: #087763; font-size: 13px; }
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
            self.status_text.setText("图标已添加，再选择一个 APK/XAPK。")

    def _choose_source(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择 APK/XAPK", "", "Android package (*.apk *.xapk)"
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
            QMessageBox.information(self, "还差一步", "请选择 APK/XAPK、图标和输出位置。")
            return
        self.settings.setValue("output", output)
        self._set_busy(True)
        self.open_button.setVisible(False)
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
            QMessageBox.information(self, "还差一步", "请选择 APK/XAPK、图标和输出位置。")
            return
        if not serial:
            QMessageBox.information(
                self,
                "请选择手机",
                "请连接手机、开启 USB 调试并授权，然后刷新并选择状态为“已授权”的设备。",
            )
            return
        self.settings.setValue("output", output)
        self._set_busy(True)
        self.open_button.setVisible(False)
        self.bundle_path = ""
        self.progress.setValue(1)
        self.status_badge.setText("准备中")
        self.status_badge.setStyleSheet("background:#e9eef5;color:#41526b")
        self.status_text.setText("正在静态扫描；通过后才会安装到所选手机…")
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
        self.device_combo.clear()
        self.device_combo.addItem("正在检查 USB 调试设备…", None)
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
        self.device_combo.clear()
        rows = list(devices)
        online_count = 0
        for row in rows:
            serial = row.get("serial", "")
            state = row.get("state", "")
            model = str(row.get("model") or row.get("device") or "Android 设备").replace("_", " ")
            if state == "device":
                self.device_combo.addItem(f"{model} · 已授权 · {serial}", serial)
                online_count += 1
            else:
                state_text = "等待手机授权" if state == "unauthorized" else state
                self.device_combo.addItem(f"{model} · {state_text} · {serial}", None)
        if not rows:
            self.device_combo.addItem("未发现设备：请连接数据线并开启 USB 调试", None)
        elif not online_count:
            self.device_combo.insertItem(0, "没有已授权设备，请查看手机弹窗", None)

    @Slot(str, str)
    def _on_device_failure(self, message: str, _detail: str) -> None:
        self.refresh_button.setEnabled(True)
        self.device_combo.clear()
        self.device_combo.addItem(f"ADB 不可用：{message}", None)

    @Slot(int, str)
    def _on_progress(self, value: int, message: str) -> None:
        self.progress.setValue(value)
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
            f"手机：{prepare_result.get('deviceModel') or '未确认'}\n"
            f"启动结果：{prepare_result.get('launchStatus') or '未确认'}\n"
            f"前台页面：{prepare_result.get('focusedActivity') or '未确认'}\n"
            f"签名证书 SHA-256：{certificate}\n\n"
            "下一步：在手机上手动完成应用 UI 截图和一段录屏。\n"
            "完成后把整个交接文件夹交给 Agent1，并回复“好了”；"
            "如果截图或录屏黑屏/被禁止，请在“好了”后明确写出来。"
        )
        self.bundle_path = bundle
        self.open_button.setVisible(True)

    @Slot(str, str)
    def _on_failure(self, message: str, detail: str) -> None:
        self._set_busy(False)
        self.status_badge.setText("失败")
        self.status_badge.setStyleSheet("background:#fee8e7;color:#a52a24")
        self.status_text.setText(message)
        self.detail_label.setText(detail)

    def _set_busy(self, busy: bool) -> None:
        self.scan_button.setEnabled(not busy)
        self.prepare_button.setEnabled(not busy)
        self.refresh_button.setEnabled(not busy)

    @Slot()
    def _thread_finished(self) -> None:
        self.worker = None
        self.thread = None

    def _open_bundle(self) -> None:
        if self.bundle_path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(self.bundle_path))

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
