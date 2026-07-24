"""PySide6 desktop interface for nontechnical editors."""

from __future__ import annotations

import sys
import threading
import traceback
from contextlib import suppress
from pathlib import Path

from PySide6.QtCore import (
    QEvent,
    QObject,
    QSettings,
    QSize,
    Qt,
    QThread,
    QTimer,
    QUrl,
    Signal,
    Slot,
)
from PySide6.QtGui import (
    QCloseEvent,
    QDesktopServices,
    QDragEnterEvent,
    QDragLeaveEvent,
    QDropEvent,
    QMouseEvent,
    QPixmap,
    QWheelEvent,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
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

from apkba_analyzer.device import AdbClient, record_media_capture_end, scan_create_and_prepare
from apkba_analyzer.finish import (
    cleanup_media_review,
    finalize_evidence,
    finish_preflight,
    prepare_media_review,
)
from apkba_analyzer.scanner import SUPPORTED_IMAGES, SUPPORTED_SOURCES


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

        header = QVBoxLayout()
        header.setSpacing(6)
        self.title = QLabel(title)
        self.title.setObjectName("dropTitle")
        self.status_label = QLabel("等待选择")
        self.status_label.setObjectName("dropStatus")
        header.addWidget(self.title)
        header.addWidget(self.status_label, 0, Qt.AlignmentFlag.AlignLeft)

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

    def clear_path(self) -> None:
        self._set_visual_state("selected", False)
        self.status_label.setText("等待选择")
        self.file_name_label.clear()
        self.file_name_label.setVisible(False)
        self.path_label.clear()
        self.path_label.setVisible(False)
        self.setToolTip("")
        self.path_label.setToolTip("")

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


class ClickableImageLabel(QLabel):
    """Small media preview that opens its original image when clicked."""

    clicked = Signal(str)

    def __init__(
        self,
        image_path: str,
        preview_size: QSize,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.image_path = image_path
        self.setFixedSize(preview_size)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip("点击查看大图")
        self.setStyleSheet(
            "background:#101722;border:1px solid #cbd6e5;border-radius:8px"
        )
        pixmap = QPixmap(image_path)
        if pixmap.isNull():
            self.setText("无法预览")
            self.setStyleSheet(
                "background:#eef2f7;color:#64748b;"
                "border:1px solid #cbd6e5;border-radius:8px"
            )
        else:
            self.setPixmap(
                pixmap.scaled(
                    preview_size,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
            )

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton and self.image_path:
            self.clicked.emit(self.image_path)
            event.accept()
            return
        super().mousePressEvent(event)


class ImagePreviewDialog(QDialog):
    """Zoomable local image viewer for screenshots and recording frames."""

    def __init__(self, image_path: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.image_path = image_path
        self.original = QPixmap(image_path)
        self.zoom_factor = 1.0
        self.setWindowTitle(f"查看大图 · {Path(image_path).name}")
        self.resize(980, 760)
        self.setMinimumSize(680, 520)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        controls = QHBoxLayout()
        name = QLabel(Path(image_path).name)
        name.setStyleSheet("font-size:15px;font-weight:700")
        controls.addWidget(name, 1)
        fit_button = QPushButton("适合窗口")
        actual_button = QPushButton("100%")
        zoom_out_button = QPushButton("缩小")
        zoom_in_button = QPushButton("放大")
        close_button = QPushButton("关闭")
        fit_button.clicked.connect(self._fit_to_window)
        actual_button.clicked.connect(lambda: self._set_zoom(1.0))
        zoom_out_button.clicked.connect(lambda: self._set_zoom(self.zoom_factor / 1.25))
        zoom_in_button.clicked.connect(lambda: self._set_zoom(self.zoom_factor * 1.25))
        close_button.clicked.connect(self.accept)
        for button in (
            fit_button,
            actual_button,
            zoom_out_button,
            zoom_in_button,
            close_button,
        ):
            controls.addWidget(button)
        layout.addLayout(controls)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(False)
        self.scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_label.setStyleSheet("background:#111827")
        self.scroll.setWidget(self.image_label)
        layout.addWidget(self.scroll, 1)

        if self.original.isNull():
            self.image_label.setText("无法读取该图片。")
            self.image_label.resize(480, 320)
        else:
            self._set_zoom(1.0)
            QTimer.singleShot(0, self._fit_to_window)

    def _set_zoom(self, factor: float) -> None:
        if self.original.isNull():
            return
        self.zoom_factor = max(0.1, min(factor, 5.0))
        target = self.original.size() * self.zoom_factor
        pixmap = self.original.scaled(
            target,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self.image_label.setPixmap(pixmap)
        self.image_label.resize(pixmap.size())

    def _fit_to_window(self) -> None:
        if self.original.isNull():
            return
        available = self.scroll.viewport().size() - QSize(20, 20)
        if available.width() <= 0 or available.height() <= 0:
            return
        factor = min(
            available.width() / self.original.width(),
            available.height() / self.original.height(),
            1.0,
        )
        self._set_zoom(factor)


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
    low_target_sdk_confirmation_required = Signal(object)

    def __init__(self, source: str, icon: str, output: str, serial: str):
        super().__init__()
        self.source = source
        self.icon = icon
        self.output = output
        self.serial = serial
        self._low_target_sdk_confirmation = threading.Event()
        self._allow_low_target_sdk_bypass = False

    def _confirm_low_target_sdk(self, details: dict[str, object]) -> bool:
        self._allow_low_target_sdk_bypass = False
        self._low_target_sdk_confirmation.clear()
        self.low_target_sdk_confirmation_required.emit(details)
        self._low_target_sdk_confirmation.wait()
        return self._allow_low_target_sdk_bypass

    def resolve_low_target_sdk_confirmation(self, allow: bool) -> None:
        self._allow_low_target_sdk_bypass = allow
        self._low_target_sdk_confirmation.set()

    @Slot()
    def run(self) -> None:
        try:
            report, bundle, result = scan_create_and_prepare(
                self.source,
                self.icon,
                self.output,
                self.serial,
                progress=lambda value, message: self.progress.emit(value, message),
                confirm_low_target_sdk=self._confirm_low_target_sdk,
            )
            self.succeeded.emit(report, result, str(bundle))
        except Exception as error:
            self.failed.emit(str(error), traceback.format_exc())


class CaptureEndWorker(QObject):
    succeeded = Signal(object)
    failed = Signal(str, str)

    def __init__(self, bundle: str, serial: str):
        super().__init__()
        self.bundle = bundle
        self.serial = serial

    @Slot()
    def run(self) -> None:
        try:
            result = record_media_capture_end(Path(self.bundle), self.serial)
            self.succeeded.emit(result)
        except Exception as error:
            self.failed.emit(str(error), traceback.format_exc())


class FinishPreflightWorker(QObject):
    succeeded = Signal(object)
    failed = Signal(str, str)

    def __init__(self, bundle: str):
        super().__init__()
        self.bundle = bundle

    @Slot()
    def run(self) -> None:
        try:
            self.succeeded.emit(finish_preflight(self.bundle))
        except Exception as error:
            self.failed.emit(str(error), traceback.format_exc())


class MediaReviewWorker(QObject):
    succeeded = Signal(object)
    failed = Signal(str, str)

    def __init__(self, bundle: str, recording_remote_path: str):
        super().__init__()
        self.bundle = bundle
        self.recording_remote_path = recording_remote_path

    @Slot()
    def run(self) -> None:
        try:
            self.succeeded.emit(
                prepare_media_review(self.bundle, self.recording_remote_path)
            )
        except Exception as error:
            self.failed.emit(str(error), traceback.format_exc())


class FinalizeWorker(QObject):
    progress = Signal(int, str)
    succeeded = Signal(object)
    failed = Signal(str, str)

    def __init__(self, review: dict[str, object], choices: dict[str, object]):
        super().__init__()
        self.review = review
        self.choices = choices

    @Slot()
    def run(self) -> None:
        try:
            self.progress.emit(84, "正在拉取确认的媒体并生成证据包…")
            result = finalize_evidence(
                str(self.review["bundlePath"]),
                list(self.choices["selectedScreenshotPaths"]),
                str(self.review["selectedRecording"]["remote_path"]),
                content_visibility=str(self.choices["contentVisibility"]),
                review_method=str(self.choices["reviewMethod"]),
                operator_reported_protected_media=bool(
                    self.choices["operatorReportedProtectedMedia"]
                ),
                local_restriction_image=(
                    str(self.choices["localRestrictionImage"])
                    if self.choices.get("localRestrictionImage")
                    else None
                ),
                output_root=str(self.choices["outputRoot"]),
                review=self.review,
            )
            self.progress.emit(100, "证据包已生成并通过验证。")
            self.succeeded.emit(result)
        except Exception as error:
            self.failed.emit(str(error), traceback.format_exc())


class MediaReviewDialog(QDialog):
    """One explicit local review replaces Agent1's filename/frame judgment."""

    def __init__(
        self,
        review: dict[str, object],
        default_output: str,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.review = review
        self.screenshot_checks: dict[str, QCheckBox] = {}
        self.media_previews: list[ClickableImageLabel] = []
        self.setWindowTitle("确认本次截图与录屏")
        self.resize(1180, 720)
        self.setMinimumSize(940, 600)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        title = QLabel(
            f"{review.get('applicationLabel') or '当前应用'} · "
            f"{review.get('packageName') or '包名未确认'}"
        )
        title.setStyleSheet("font-size:20px;font-weight:750")
        help_text = QLabel(
            "只勾选属于本次应用、设置或权限页面的截图。"
            "录屏分类必须根据下方代表帧或完整回放确认。"
        )
        help_text.setWordWrap(True)
        help_text.setStyleSheet("color:#58677d")
        layout.addWidget(title)
        layout.addWidget(help_text)

        media_layout = QHBoxLayout()
        media_layout.setSpacing(14)

        screenshot_group = QGroupBox("截图（逐张确认）")
        screenshot_layout = QVBoxLayout(screenshot_group)
        screenshot_hint = QLabel("点击任意缩略图可查看大图；只勾选属于本次应用的截图。")
        screenshot_hint.setStyleSheet("color:#58677d")
        screenshot_hint.setWordWrap(True)
        screenshot_layout.addWidget(screenshot_hint)
        screenshot_scroll = QScrollArea()
        screenshot_scroll.setWidgetResizable(True)
        screenshot_scroll.setMinimumHeight(360)
        screenshot_content = QWidget()
        screenshot_rows = QGridLayout(screenshot_content)
        screenshot_rows.setHorizontalSpacing(14)
        screenshot_rows.setVerticalSpacing(16)
        screenshots = list(review.get("screenshots") or [])
        suggested = set(review.get("suggestedScreenshotPaths") or [])
        default_all = not suggested
        for index, record in enumerate(screenshots):
            remote_path = str(record.get("remote_path") or "")
            check = QCheckBox(str(record.get("file_name") or Path(remote_path).name))
            check.setChecked(default_all or remote_path in suggested)
            check.setToolTip(remote_path)
            self.screenshot_checks[remote_path] = check
            card = QWidget()
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(4, 4, 4, 4)
            card_layout.setSpacing(7)
            local_path = str(record.get("localPath") or "")
            preview = ClickableImageLabel(local_path, QSize(138, 230))
            preview.clicked.connect(self._open_image_preview)
            self.media_previews.append(preview)
            card_layout.addWidget(preview, 0, Qt.AlignmentFlag.AlignCenter)
            card_layout.addWidget(check)
            row_index, column_index = divmod(index, 3)
            screenshot_rows.addWidget(card, row_index, column_index)
        if not screenshots:
            screenshot_rows.addWidget(QLabel("本次边界内没有发现设备截图。"), 0, 0, 1, 3)
        for column_index in range(3):
            screenshot_rows.setColumnStretch(column_index, 1)
        screenshot_scroll.setWidget(screenshot_content)
        screenshot_layout.addWidget(screenshot_scroll)

        restriction_row = QHBoxLayout()
        restriction_label = QLabel("截图被禁止时的本地说明图")
        self.restriction_edit = QLineEdit()
        self.restriction_edit.setPlaceholderText("正常有截图时留空")
        restriction_button = QPushButton("选择…")
        restriction_button.clicked.connect(self._choose_restriction_image)
        restriction_row.addWidget(restriction_label)
        restriction_row.addWidget(self.restriction_edit, 1)
        restriction_row.addWidget(restriction_button)
        screenshot_layout.addLayout(restriction_row)
        media_layout.addWidget(screenshot_group, 3)

        recording_group = QGroupBox("录屏内容审查")
        recording_layout = QVBoxLayout(recording_group)
        recording_name = QLabel(
            str((review.get("selectedRecording") or {}).get("file_name") or "当前录屏")
        )
        recording_name.setStyleSheet("font-weight:700")
        recording_layout.addWidget(recording_name)
        recording_hint = QLabel("点击代表帧可查看大图；需要时可打开完整录屏核对。")
        recording_hint.setStyleSheet("color:#58677d")
        recording_hint.setWordWrap(True)
        recording_layout.addWidget(recording_hint)
        frame_scroll = QScrollArea()
        frame_scroll.setWidgetResizable(True)
        frame_scroll.setMinimumHeight(330)
        frame_content = QWidget()
        frame_grid = QGridLayout(frame_content)
        frame_grid.setHorizontalSpacing(10)
        frame_grid.setVerticalSpacing(12)
        frames = list(review.get("recordingFrames") or [])
        for index, frame_path in enumerate(frames):
            preview = ClickableImageLabel(str(frame_path), QSize(145, 245))
            preview.clicked.connect(self._open_image_preview)
            self.media_previews.append(preview)
            row_index, column_index = divmod(index, 2)
            frame_grid.addWidget(preview, row_index, column_index)
        if not frames:
            missing_frames = QLabel(
                "未能生成代表帧，请点击“打开完整录屏”并在播放器中确认。"
            )
            missing_frames.setWordWrap(True)
            frame_grid.addWidget(missing_frames, 0, 0, 1, 2)
        frame_grid.setColumnStretch(0, 1)
        frame_grid.setColumnStretch(1, 1)
        frame_scroll.setWidget(frame_content)
        recording_layout.addWidget(frame_scroll, 1)
        recording_controls = QHBoxLayout()
        open_recording = QPushButton("打开完整录屏")
        open_recording.clicked.connect(self._open_recording)
        recording_controls.addWidget(open_recording)
        recording_controls.addWidget(QLabel("内容分类"))
        self.visibility_combo = QComboBox()
        self.visibility_combo.addItem("可见应用内部 UI", "visible")
        self.visibility_combo.addItem("黑屏 / 禁止录屏", "protected_black_screen")
        self.visibility_combo.addItem(
            "部分可见但含受保护内容",
            "partially_visible_protected_content",
        )
        suggestion = review.get("visibilitySuggestion")
        suggested_index = self.visibility_combo.findData(suggestion)
        if suggested_index >= 0:
            self.visibility_combo.setCurrentIndex(suggested_index)
        recording_controls.addWidget(self.visibility_combo, 1)
        recording_layout.addLayout(recording_controls)
        suggestion_text = (
            "程序帧分析建议：黑屏 / 受保护"
            if suggestion == "protected_black_screen"
            else "程序帧分析建议：可见"
            if suggestion == "visible"
            else "程序未能自动判断，请回放确认"
        )
        self.suggestion_label = QLabel(suggestion_text)
        self.suggestion_label.setStyleSheet("color:#7d5800")
        recording_layout.addWidget(self.suggestion_label)
        media_layout.addWidget(recording_group, 2)
        layout.addLayout(media_layout, 1)

        output_row = QHBoxLayout()
        output_row.addWidget(QLabel("最终证据包位置"))
        self.output_edit = QLineEdit(default_output)
        self.output_edit.setPlaceholderText("选择最终证据包保存根目录")
        output_button = QPushButton("浏览…")
        output_button.clicked.connect(self._choose_output_root)
        output_row.addWidget(self.output_edit, 1)
        output_row.addWidget(output_button)
        layout.addLayout(output_row)

        self.confirm_check = QCheckBox(
            "我已检查勾选的截图和录屏代表帧/完整回放，确认均属于本次应用取证"
        )
        layout.addWidget(self.confirm_check)
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok
        )
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("生成证据包")
        self.buttons.accepted.connect(self._validate_and_accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    def _choose_restriction_image(self) -> None:
        path, _filter = QFileDialog.getOpenFileName(
            self,
            "选择截图被禁止的说明图片",
            "",
            "Images (*.png *.jpg *.jpeg *.webp *.avif)",
        )
        if path:
            self.restriction_edit.setText(path)

    def _open_recording(self) -> None:
        path = str(self.review.get("localRecordingPath") or "")
        if path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    @Slot(str)
    def _open_image_preview(self, image_path: str) -> None:
        ImagePreviewDialog(image_path, self).exec()

    def _choose_output_root(self) -> None:
        path = QFileDialog.getExistingDirectory(
            self,
            "选择最终证据包保存位置",
            self.output_edit.text(),
        )
        if path:
            self.output_edit.setText(path)

    def _validate_and_accept(self) -> None:
        selected = [
            remote_path
            for remote_path, check in self.screenshot_checks.items()
            if check.isChecked()
        ]
        restriction = self.restriction_edit.text().strip()
        visibility = str(self.visibility_combo.currentData() or "")
        frames = list(self.review.get("recordingFrames") or [])
        output_root = self.output_edit.text().strip()
        if not selected and not restriction:
            QMessageBox.information(
                self,
                "还差截图证据",
                "请至少勾选一张截图；如果应用禁止截图，请选择本地说明图片。",
            )
            return
        if not output_root:
            QMessageBox.information(self, "请选择保存位置", "请选择最终证据包保存根目录。")
            return
        if visibility != "visible" and not frames:
            QMessageBox.information(
                self,
                "缺少代表帧",
                "受保护录屏必须同时检查代表帧。当前无法生成代表帧，"
                "请先在电脑安装 ffmpeg 后重新审查。",
            )
            return
        if not self.confirm_check.isChecked():
            QMessageBox.information(self, "请确认审查", "请勾选最后一项确认后再生成。")
            return
        self.accept()

    def choices(self) -> dict[str, object]:
        visibility = str(self.visibility_combo.currentData())
        protected = visibility != "visible"
        frames = list(self.review.get("recordingFrames") or [])
        if protected:
            review_method = "representative_frame_and_operator_report"
        elif frames:
            review_method = "representative_frame_visual_review"
        else:
            review_method = "operator_confirmed_playback"
        return {
            "selectedScreenshotPaths": [
                remote_path
                for remote_path, check in self.screenshot_checks.items()
                if check.isChecked()
            ],
            "localRestrictionImage": self.restriction_edit.text().strip() or None,
            "contentVisibility": visibility,
            "reviewMethod": review_method,
            "operatorReportedProtectedMedia": protected,
            "outputRoot": self.output_edit.text().strip(),
        }


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.source_path = ""
        self.icon_path = ""
        self.bundle_path = ""
        self._selected_device_serial: str | None = None
        self._active_device_serial: str | None = None
        self._active_device_display = ""
        self._capture_bundle_path = ""
        self._capture_device_serial = ""
        self._capture_device_display = ""
        self._capture_completed = False
        self._finish_bundle_path = ""
        self._finish_review: dict[str, object] | None = None
        self._deferred_action: object | None = None
        self.thread: QThread | None = None
        self.worker: QObject | None = None
        self.settings = QSettings("APKBA", "APKBA Analyzer")
        self.setWindowTitle("APKBA Analyzer")
        self.setAcceptDrops(True)
        self.resize(1080, 760)
        self.setMinimumSize(880, 640)
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
        layout.setSpacing(14)

        self.input_section = QFrame()
        self.input_section.setObjectName("sectionPanel")
        input_column = QVBoxLayout(self.input_section)
        input_column.setContentsMargins(18, 16, 18, 18)
        input_column.setSpacing(12)
        input_title = QLabel("1 · 准备文件")
        input_title.setObjectName("sectionTitle")
        input_hint = QLabel("拖入安装包和对应图标，或使用下方按钮选择。")
        input_hint.setObjectName("sectionHint")
        input_hint.setWordWrap(True)
        input_column.addWidget(input_title)
        input_column.addWidget(input_hint)

        cards = QGridLayout()
        cards.setHorizontalSpacing(12)
        cards.setVerticalSpacing(10)
        self.source_card = DropCard(
            "安装包",
            "APK / XAPK / APKM · 拖拽或选择",
            SUPPORTED_SOURCES,
        )
        self.icon_card = DropCard(
            "应用图标",
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
        cards.setColumnStretch(0, 1)
        cards.setColumnStretch(1, 1)
        input_column.addLayout(cards)

        self.workflow_section = QFrame()
        self.workflow_section.setObjectName("sectionPanel")
        workflow_column = QVBoxLayout(self.workflow_section)
        workflow_column.setContentsMargins(18, 16, 18, 18)
        workflow_column.setSpacing(12)
        workflow_title = QLabel("2 · 连接、取证与完成")
        workflow_title.setObjectName("sectionTitle")
        workflow_hint = QLabel("选择交接包输出位置与当前窗口使用的手机。")
        workflow_hint.setObjectName("sectionHint")
        workflow_hint.setWordWrap(True)
        workflow_column.addWidget(workflow_title)
        workflow_column.addWidget(workflow_hint)

        configuration_column = QVBoxLayout()
        configuration_column.setSpacing(10)
        self.output_frame = QFrame()
        self.output_frame.setObjectName("panel")
        output_layout = QHBoxLayout(self.output_frame)
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
        configuration_column.addWidget(self.output_frame)

        self.device_frame = QFrame()
        self.device_frame.setObjectName("panel")
        device_layout = QHBoxLayout(self.device_frame)
        device_layout.setContentsMargins(14, 10, 14, 10)
        device_label = QLabel("本窗口手机")
        device_label.setObjectName("fieldLabel")
        self.device_combo = DeviceComboBox()
        self.device_combo.addItem("正在检查 USB 调试设备…", None)
        self.device_combo.setMinimumWidth(180)
        self.device_combo.setToolTip("每个窗口单独选择并绑定一台手机")
        self.device_combo.currentIndexChanged.connect(self._on_device_selection_changed)
        self.refresh_button = QPushButton("刷新")
        self.refresh_button.clicked.connect(self._refresh_devices)
        device_layout.addWidget(device_label)
        device_layout.addWidget(self.device_combo, 1)
        device_layout.addWidget(self.refresh_button)
        configuration_column.addWidget(self.device_frame)
        workflow_column.addLayout(configuration_column)

        action_row = QHBoxLayout()
        self.prepare_button = QPushButton("连接手机取证")
        self.prepare_button.setObjectName("primaryButton")
        self.prepare_button.setMinimumHeight(42)
        self.prepare_button.clicked.connect(self._start_prepare)
        action_row.addStretch()
        action_row.addWidget(self.prepare_button)
        workflow_column.addLayout(action_row)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        workflow_column.addWidget(self.progress)

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
        self.capture_button = QPushButton("截图/录屏完成 · 记录边界")
        self.capture_button.setObjectName("captureButton")
        self.capture_button.setVisible(False)
        self.capture_button.clicked.connect(self._start_capture_end)
        result_layout.addWidget(self.capture_button)
        result_actions = QHBoxLayout()
        self.finish_button = QPushButton("完成已有取证")
        self.finish_button.clicked.connect(self._start_finish)
        result_actions.addWidget(self.finish_button)
        result_actions.addWidget(self.open_button)
        result_actions.addStretch()
        result_layout.addLayout(result_actions)
        workflow_column.addWidget(self.result_panel, 1)

        layout.addWidget(self.input_section)
        layout.addWidget(self.workflow_section, 1)

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
            QLabel#sectionTitle { font-size: 19px; font-weight: 750; color: #17233b; }
            QLabel#sectionHint { color: #64748b; }
            QFrame#sectionPanel {
                background: white; border: 1px solid #dfe6ef; border-radius: 16px;
            }
            QFrame#panel, QFrame#resultPanel {
                background: #f8fafc; border: 1px solid #dfe6ef; border-radius: 12px;
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
            QPushButton#captureButton {
                background: #087763; color: white; border-color: #087763; font-weight: 750;
            }
            QPushButton#captureButton:hover { background: #066653; }
            QPushButton#captureButton:disabled {
                background: #dce6e3; color: #58716a; border-color: #c7d6d2;
            }
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

    def _require_capture_end_before_next_task(self) -> bool:
        if not self._capture_bundle_path or self._capture_completed:
            return True
        QMessageBox.information(
            self,
            "请先记录本次取证边界",
            "当前 APK 仍在等待截图/录屏完成。请先点击“截图/录屏完成 · 记录边界”，"
            "再开始下一份 APK，避免两次取证媒体混在一起。",
        )
        return False

    def _start_prepare(self) -> None:
        output = self.output_edit.text().strip()
        serial = self.device_combo.currentData()
        if not self._require_capture_end_before_next_task():
            return
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
        self._reset_capture_state()
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
        self.worker.low_target_sdk_confirmation_required.connect(
            self._on_low_target_sdk_confirmation_required
        )
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
        bypass = prepare_result.get("lowTargetSdkBypass") or {}
        bypass_text = ""
        if prepare_result.get("lowTargetSdkBypassUsed"):
            bypass_text = (
                "\n低目标 SDK 兼容安装：已人工确认"
                f"（target {bypass.get('target_sdk')}，"
                f"手机要求至少 {bypass.get('device_minimum_target_sdk')}）"
            )
        self.detail_label.setText(
            f"应用：{app.get('applicationLabel') or '未确认'}\n"
            f"包名：{app.get('packageName') or '未确认'}\n"
            f"手机：{prepare_result.get('deviceModel') or '未确认'}"
            f" · {prepare_result.get('deviceSerial') or '序列号未确认'}\n"
            f"启动结果：{prepare_result.get('launchStatus') or '未确认'}\n"
            f"前台页面：{prepare_result.get('focusedActivity') or '未确认'}\n"
            f"签名证书 SHA-256：{certificate}"
            f"{bypass_text}\n\n"
            "下一步：在手机上手动完成应用 UI 截图和一段录屏。\n"
            "完成后点击“截图/录屏完成 · 记录边界”，程序会继续媒体审查和证据包生成。"
        )
        self.bundle_path = bundle
        self._capture_bundle_path = bundle
        self._capture_device_serial = str(prepare_result.get("deviceSerial") or "")
        self._capture_device_display = (
            f"{prepare_result.get('deviceModel') or '未确认'} · "
            f"{self._capture_device_serial or '序列号未确认'}"
        )
        self._capture_completed = False
        self.capture_button.setText("截图/录屏完成 · 记录边界")
        self.capture_button.setVisible(True)
        self.capture_button.setEnabled(True)
        self.open_button.setVisible(True)

    @Slot(object)
    def _on_low_target_sdk_confirmation_required(self, details: object) -> None:
        requirement = dict(details)
        message_box = QMessageBox(self)
        message_box.setIcon(QMessageBox.Icon.Warning)
        message_box.setWindowTitle("低目标 SDK 应用")
        message_box.setText(
            f"该 APK 的 targetSdk 是 {requirement.get('target_sdk')}，"
            f"手机系统要求至少 {requirement.get('device_minimum_target_sdk')}。"
        )
        message_box.setInformativeText(
            "Android 阻止这类旧应用，是因为它可能绕过较新的权限和隐私保护。"
            "仅应在当前测试手机上进行兼容测试；安装后应用仍可能无法正常运行。"
        )
        install_button = message_box.addButton(
            "兼容安装",
            QMessageBox.ButtonRole.AcceptRole,
        )
        cancel_button = message_box.addButton(
            "取消",
            QMessageBox.ButtonRole.RejectRole,
        )
        message_box.setDefaultButton(cancel_button)
        message_box.exec()
        allow = message_box.clickedButton() is install_button
        worker = self.worker
        if isinstance(worker, PrepareWorker):
            worker.resolve_low_target_sdk_confirmation(allow)

    def _start_capture_end(self) -> None:
        if not self._capture_bundle_path or not self._capture_device_serial:
            QMessageBox.information(self, "没有待记录的取证", "请先完成一次“连接手机取证”。")
            return
        self._active_device_serial = self._capture_device_serial
        self._active_device_display = self._capture_device_display
        self._set_busy(True)
        self.status_badge.setText("记录中")
        self.status_badge.setStyleSheet("background:#e9eef5;color:#41526b")
        self.status_text.setText(
            f"正在读取截图/录屏结束边界 ｜ 目标：{self._capture_device_display}"
        )
        self.thread = QThread(self)
        self.worker = CaptureEndWorker(
            self._capture_bundle_path,
            self._capture_device_serial,
        )
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.succeeded.connect(self._on_capture_end_success)
        self.worker.failed.connect(self._on_failure)
        self.worker.succeeded.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self._thread_finished)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    @Slot(object)
    def _on_capture_end_success(self, result: object) -> None:
        self._set_busy(False)
        capture_result = dict(result)
        screenshot_count = int(capture_result.get("screenshotCount") or 0)
        recording_count = int(capture_result.get("recordingCount") or 0)
        self._capture_completed = True
        self.source_path = ""
        self.icon_path = ""
        self.source_card.clear_path()
        self.icon_card.clear_path()
        self.capture_button.setText("✓ 本次取证边界已记录")
        self.capture_button.setEnabled(False)
        if screenshot_count and recording_count:
            self.status_badge.setText("本次已封口")
            self.status_badge.setStyleSheet("background:#ddf7ee;color:#087763")
            self.status_text.setText("结束边界已记录，可以直接拖入下一份 APK 和图标。")
        else:
            missing = []
            if not screenshot_count:
                missing.append("截图")
            if not recording_count:
                missing.append("录屏")
            self.status_badge.setText("边界已记录 · 有提醒")
            self.status_badge.setStyleSheet("background:#fff2cf;color:#7d5800")
            self.status_text.setText(
                f"已记录结束边界，但未发现新增{'和'.join(missing)}；"
                "如属黑屏/禁止截图，请在交接时说明。"
            )
        self.detail_label.setText(
            f"手机：{capture_result.get('deviceModel') or '未确认'}"
            f" · {capture_result.get('deviceSerial') or '序列号未确认'}\n"
            f"结束时间：{capture_result.get('deviceTime') or '未确认'}\n"
            f"本次边界内媒体：截图 {screenshot_count} 张 · 录屏 {recording_count} 段\n\n"
            "程序将只读取“准备前基线”之后、这次结束边界之前的媒体，"
            "下一份 APK 的截图和录屏不会混入本次。"
        )
        self.finish_button.setText("审查媒体并生成证据包")
        self.finish_button.setEnabled(True)
        self._finish_bundle_path = self._capture_bundle_path
        self._run_after_current_thread(self._start_finish)

    def _start_finish(self) -> None:
        candidate = (
            self._finish_bundle_path
            or self._capture_bundle_path
            or (
                self.bundle_path
                if self.bundle_path
                and (Path(self.bundle_path) / ".apkba-pending-session.json").is_file()
                else ""
            )
        )
        if not candidate:
            candidate = QFileDialog.getExistingDirectory(
                self,
                "选择含 .apkba-pending-session.json 的交接文件夹",
                self.output_edit.text(),
            )
        if not candidate:
            return
        pending_path = Path(candidate) / ".apkba-pending-session.json"
        if not pending_path.is_file():
            QMessageBox.information(
                self,
                "不是待完成交接包",
                "所选文件夹中没有 .apkba-pending-session.json。",
            )
            return
        self._finish_bundle_path = str(Path(candidate).resolve())
        self._set_busy(True)
        self.progress.setValue(72)
        self.status_badge.setText("媒体预检")
        self.status_badge.setStyleSheet("background:#e9eef5;color:#41526b")
        self.status_text.setText("正在冻结结束边界并核对本次截图和录屏…")
        self.thread = QThread(self)
        self.worker = FinishPreflightWorker(self._finish_bundle_path)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.succeeded.connect(self._on_finish_preflight_success)
        self.worker.failed.connect(self._on_failure)
        self.worker.succeeded.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self._thread_finished)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    @Slot(object)
    def _on_finish_preflight_success(self, result: object) -> None:
        preflight = dict(result)
        recordings = list(preflight.get("recordings") or [])
        if not recordings:
            self._set_busy(False)
            self.status_badge.setText("缺少录屏")
            self.status_badge.setStyleSheet("background:#fff2cf;color:#7d5800")
            self.status_text.setText("本次基线和结束边界之间没有发现录屏，尚未生成证据包。")
            self.detail_label.setText(
                "请在手机上为当前应用补录一段视频。由于结束边界已经封口，"
                "补录后需要重新开始该应用的一次取证，避免混入下一任务媒体。"
            )
            return
        if len(recordings) == 1:
            selected_recording = recordings[0]
        else:
            labels = [
                f"{record.get('file_name')} · {record.get('size_bytes')} bytes"
                for record in recordings
            ]
            selected_label, accepted = QInputDialog.getItem(
                self,
                "选择本次录屏",
                "发现多段录屏，请选择属于当前应用的一段：",
                labels,
                0,
                False,
            )
            if not accepted:
                self._set_busy(False)
                self.status_text.setText("已取消媒体审查，取证会话仍保留。")
                return
            selected_recording = recordings[labels.index(selected_label)]
        self._finish_bundle_path = str(preflight["bundlePath"])
        recording_path = str(selected_recording["remote_path"])
        self._run_after_current_thread(
            lambda: self._start_media_review(recording_path)
        )

    def _start_media_review(self, recording_remote_path: str) -> None:
        self._set_busy(True)
        self.progress.setValue(78)
        self.status_badge.setText("读取媒体")
        self.status_text.setText("正在拉取截图缩略图和录屏代表帧供本机审查…")
        self.thread = QThread(self)
        self.worker = MediaReviewWorker(
            self._finish_bundle_path,
            recording_remote_path,
        )
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.succeeded.connect(self._on_media_review_ready)
        self.worker.failed.connect(self._on_failure)
        self.worker.succeeded.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self._thread_finished)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    @Slot(object)
    def _on_media_review_ready(self, result: object) -> None:
        self._set_busy(False)
        review = dict(result)
        self._finish_review = review
        default_output = str(
            self.settings.value("evidence_output", self.output_edit.text())
        )
        dialog = MediaReviewDialog(review, default_output, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            with suppress(Exception):
                cleanup_media_review(str(review["reviewRoot"]))
            self._finish_review = None
            self.status_badge.setText("尚未完成")
            self.status_badge.setStyleSheet("background:#fff2cf;color:#7d5800")
            self.status_text.setText("已取消生成；pending-session 和原始输入均保留。")
            return
        choices = dialog.choices()
        self.settings.setValue("evidence_output", str(choices["outputRoot"]))
        self._run_after_current_thread(lambda: self._start_finalize(review, choices))

    def _start_finalize(
        self,
        review: dict[str, object],
        choices: dict[str, object],
    ) -> None:
        self._set_busy(True)
        self.progress.setValue(82)
        self.status_badge.setText("生成中")
        self.status_badge.setStyleSheet("background:#e9eef5;color:#41526b")
        self.status_text.setText("正在创建并验证 schema3 证据包…")
        self.thread = QThread(self)
        self.worker = FinalizeWorker(review, choices)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._on_progress)
        self.worker.succeeded.connect(self._on_finalize_success)
        self.worker.failed.connect(self._on_failure)
        self.worker.succeeded.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self._thread_finished)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    @Slot(object)
    def _on_finalize_success(self, result: object) -> None:
        self._set_busy(False)
        final = dict(result)
        if self._finish_review:
            with suppress(Exception):
                cleanup_media_review(str(self._finish_review["reviewRoot"]))
        self._finish_review = None
        self.bundle_path = str(final["packagePath"])
        self._finish_bundle_path = ""
        self._capture_bundle_path = ""
        self._capture_completed = True
        self.progress.setValue(100)
        self.status_badge.setText("证据包完成")
        self.status_badge.setStyleSheet("background:#ddf7ee;color:#087763")
        self.status_text.setText("证据包已生成并通过本地验证，可直接交给 Agent2。")
        self.detail_label.setText(
            f"证据包：{final.get('packagePath')}\n"
            f"截图：{final.get('screenshotCount')} 张\n"
            f"录屏：{final.get('recordingStatus')}\n"
            f"源包 SHA-256：{final.get('sourceSha256')}\n\n"
            "原始 APK/XAPK、图标和 intake 记录均保留；"
            "程序只清除了已完成的 pending-session。"
        )
        self.capture_button.setVisible(False)
        self.finish_button.setText("完成已有取证")
        self.finish_button.setEnabled(True)
        self.open_button.setVisible(True)

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
        self.prepare_button.setEnabled(not busy)
        self.refresh_button.setEnabled(not busy)
        self.device_combo.setEnabled(not busy)
        self.capture_button.setEnabled(
            not busy and bool(self._capture_bundle_path) and not self._capture_completed
        )
        self.finish_button.setEnabled(not busy)

    def _reset_capture_state(self) -> None:
        self._capture_bundle_path = ""
        self._capture_device_serial = ""
        self._capture_device_display = ""
        self._capture_completed = False
        self.capture_button.setVisible(False)
        self.capture_button.setText("截图/录屏完成 · 记录边界")

    @Slot()
    def _thread_finished(self) -> None:
        self.worker = None
        self.thread = None
        self._active_device_serial = None
        self._active_device_display = ""
        deferred = self._deferred_action
        self._deferred_action = None
        if callable(deferred):
            QTimer.singleShot(0, deferred)

    def _run_after_current_thread(self, callback: object) -> None:
        if self.thread and self.thread.isRunning():
            self._deferred_action = callback
        elif callable(callback):
            QTimer.singleShot(0, callback)

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
