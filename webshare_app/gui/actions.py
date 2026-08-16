from __future__ import annotations

# pyright: reportAttributeAccessIssue=false, reportArgumentType=false

import io
import os
import socket
import sys
import webbrowser

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QComboBox, QCheckBox, QTabWidget,
    QTextEdit, QFileDialog, QMessageBox, QGroupBox, QSystemTrayIcon, QMenu,
    QScrollArea, QDialog,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QAction, QPixmap

from config import APP_TITLE, APP_VERSION, MAX_LOG_LINES, STATS, conf
from security.auth import hash_password
from server import get_server_startup_error, is_server_running, start_server, stop_server
from utils.log_manager import logger


class GuiActionsMixin:
    def update_stats(self):
            """실시간 통계 업데이트"""
            if hasattr(self, 'stats_requests'):
                self.stats_requests.setText(f"요청: {STATS['requests']}")
            if hasattr(self, 'stats_connections'):
                self.stats_connections.setText(f"접속: {STATS['active_connections']}")
            if hasattr(self, 'stats_traffic'):
                # 트래픽 포맷팅
                total_bytes = STATS['bytes_sent'] + STATS['bytes_received']
                if total_bytes < 1024:
                    traffic_str = f"{total_bytes} B"
                elif total_bytes < 1024 * 1024:
                    traffic_str = f"{total_bytes / 1024:.1f} KB"
                elif total_bytes < 1024 * 1024 * 1024:
                    traffic_str = f"{total_bytes / 1024 / 1024:.1f} MB"
                else:
                    traffic_str = f"{total_bytes / 1024 / 1024 / 1024:.2f} GB"
                self.stats_traffic.setText(f"트래픽: {traffic_str}")

    def filter_logs(self, level):
            """로그 레벨별 필터링"""
            self.log_text.clear()
            for log in self.all_logs:
                if level == "전체" or f"[{level}]" in log:
                    self.log_text.append(log)

    def export_logs(self):
            """로그 파일로 내보내기"""
            from datetime import datetime
            filename = f"webshare_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            filepath, _ = QFileDialog.getSaveFileName(self, "로그 저장", filename, "Text Files (*.txt)")
            if filepath:
                try:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write('\n'.join(self.all_logs))
                    QMessageBox.information(self, "저장 완료", f"로그가 저장되었습니다.\n{filepath}")
                except IOError as e:
                    QMessageBox.critical(self, "오류", f"저장 실패: {e}")

    def clear_logs(self):
            """로그 클리어"""
            self.log_text.clear()
            self.all_logs.clear()

    def get_ip_list(self):
            """사용 가능한 IP 목록 가져오기"""
            ips = ['127.0.0.1']
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.1)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                if ip and not ip.startswith('127.'):
                    ips.insert(0, ip)
                s.close()
            except Exception:
                pass

            try:
                host_name = socket.gethostname()
                for ip in socket.gethostbyname_ex(host_name)[2]:
                    if ip and not ip.startswith("127.") and ip not in ips:
                        ips.append(ip)
            except Exception:
                pass

            ips.append('0.0.0.0')
            return ips

    def get_local_ip(self):
            """로컬 IP 주소 가져오기"""
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                return ip
            except Exception:
                return "127.0.0.1"

    def toggle_server(self):
            """서버 시작/중지"""
            if is_server_running():
                self.toggle_btn.setEnabled(False)
                self.toggle_btn.setText("⏳ 중지 중...")

                # 비동기 종료 (UI 블로킹 방지)
                def do_shutdown():
                    stop_server()
                    self.update_ui_state(False)
                    self.toggle_btn.setEnabled(True)

                QTimer.singleShot(10, do_shutdown)
            else:
                self.save_settings()
                if not os.path.exists(conf.get('folder')):
                    QMessageBox.critical(self, "오류", "공유 폴더 경로가 잘못되었습니다.")
                    return

                self.toggle_btn.setEnabled(False)
                self.toggle_btn.setText("⏳ 시작 중...")
                QApplication.processEvents()

                if start_server(use_https=conf.get('use_https', False), wait_ready=True, timeout=5.0):
                    self.update_ui_state(True)
                else:
                    self.update_ui_state(False)
                    QMessageBox.critical(self, "오류", get_server_startup_error() or "서버 시작에 실패했습니다.")

    def update_ui_state(self, running):
            """UI 상태 업데이트"""
            if self.is_closing:
                return
            self.toggle_btn.setEnabled(True)

            if running:
                self.toggle_btn.setText("⏹  서버 중지")
                self.toggle_btn.setObjectName("stopBtn")
                self.toggle_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #ef4444;
                        font-size: 16px;
                        font-weight: bold;
                    }
                    QPushButton:hover { background-color: #f87171; }
                """)
                self.status_label.setText("🟢 서버 실행 중")
                self.status_label.setStyleSheet("color: #22c55e;")

                proto = "https" if conf.get('use_https') else "http"
                display_host = conf.get('display_host', '0.0.0.0')
                if display_host == '0.0.0.0':
                    display_host = self.get_local_ip()
                url = f"{proto}://{display_host}:{conf.get('port')}"
                self.url_label.setText(url)
            else:
                self.toggle_btn.setText("▶  서버 시작")
                self.toggle_btn.setObjectName("")
                self.toggle_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #4f46e5;
                        font-size: 16px;
                        font-weight: bold;
                    }
                    QPushButton:hover { background-color: #6366f1; }
                """)
                self.status_label.setText("⏹ 서버 중지됨")
                self.status_label.setStyleSheet("color: #94a3b8;")
                self.url_label.setText("-")

    def open_browser(self):
            """브라우저 열기"""
            url = self.url_label.text()
            if url != "-":
                webbrowser.open(url)

    def open_shared_folder(self):
            """공유 폴더를 파일 탐색기에서 열기"""
            folder = conf.get('folder')
            if folder and os.path.exists(folder):
                try:
                    os.startfile(folder)
                except AttributeError:
                    # macOS/Linux
                    import subprocess
                    subprocess.Popen(['open' if sys.platform == 'darwin' else 'xdg-open', folder])
            else:
                QMessageBox.warning(self, "경고", "공유 폴더가 존재하지 않습니다.")

    def show_qr(self):
            """QR 코드 표시"""
            url = self.url_label.text()
            if url == "-":
                return
            try:
                import qrcode
                qr = qrcode.make(url)

                dialog = QDialog(self)
                dialog.setWindowTitle("QR Code")
                dialog.setFixedSize(300, 340)
                dialog.setStyleSheet("background-color: white;")

                layout = QVBoxLayout(dialog)

                # Convert PIL image to QPixmap
                qr_bytes = io.BytesIO()
                qr.save(qr_bytes, 'PNG')
                qr_bytes.seek(0)

                pixmap = QPixmap()
                pixmap.loadFromData(qr_bytes.read())
                pixmap = pixmap.scaled(250, 250, Qt.AspectRatioMode.KeepAspectRatio)

                qr_label = QLabel()
                qr_label.setPixmap(pixmap)
                qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                layout.addWidget(qr_label)

                text_label = QLabel("모바일로 스캔하여 접속하세요")
                text_label.setStyleSheet("color: #333; font-size: 12px;")
                text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                layout.addWidget(text_label)

                dialog.exec()
            except ImportError:
                QMessageBox.critical(self, "오류", "qrcode 라이브러리가 설치되지 않았습니다.\npip install qrcode")

    def choose_folder(self):
            """폴더 선택 다이얼로그"""
            path = QFileDialog.getExistingDirectory(self, "공유 폴더 선택")
            if path:
                self.folder_input.setText(os.path.abspath(path))

    def save_settings(self):
            """설정 저장"""
            try:
                conf.set('folder', self.folder_input.text())
                conf.set('display_host', self.ip_combo.currentText())
                conf.set('port', int(self.port_input.text()))
                admin_password = self.admin_pw.text()
                guest_password = self.guest_pw.text()
                if admin_password:
                    conf.set('admin_pw', hash_password(admin_password))
                if guest_password:
                    conf.set('guest_pw', hash_password(guest_password))
                conf.set('allow_guest_upload', self.guest_upload_check.isChecked())
                conf.set('use_https', self.https_check.isChecked())
                conf.set('enable_versioning', self.versioning_check.isChecked())
                conf.set('enable_notifications', self.notification_check.isChecked())
                conf.set('minimize_to_tray', self.tray_check.isChecked())
                conf.set('close_to_tray', self.close_tray_check.isChecked())
                conf.set('autostart', self.autostart_check.isChecked())
                conf.set('session_timeout', int(self.timeout_input.text()))
                conf.save()

                QMessageBox.information(self, "저장됨", "설정이 저장되었습니다.\n일부 설정은 재시작 후 적용됩니다.")
                logger.add("설정 저장됨")
            except ValueError:
                QMessageBox.warning(self, "오류", "포트와 세션 타임아웃은 숫자여야 합니다.")
            except Exception as e:
                QMessageBox.critical(self, "오류", f"설정 저장 실패: {e}")

    def process_logs(self):
            """로그 큐 처리"""
            if self.is_closing:
                return
            try:
                current_filter = self.log_filter.currentText() if hasattr(self, 'log_filter') else "전체"
                while not logger.queue.empty():
                    msg = logger.queue.get_nowait()
                    # 모든 로그 저장
                    self.all_logs.append(msg)
                    # 최대 로그 수 제한
                    if len(self.all_logs) > MAX_LOG_LINES:
                        self.all_logs = self.all_logs[-MAX_LOG_LINES:]

                    # 필터 적용
                    if current_filter == "전체" or f"[{current_filter}]" in msg:
                        self.log_text.append(msg)

                    # Limit log lines in display
                    doc = self.log_text.document()
                    if doc is not None and doc.blockCount() > MAX_LOG_LINES:
                        cursor = self.log_text.textCursor()
                        cursor.movePosition(cursor.MoveOperation.Start)
                        cursor.movePosition(cursor.MoveOperation.Down, cursor.MoveMode.KeepAnchor,
                                          doc.blockCount() - MAX_LOG_LINES)
                        cursor.removeSelectedText()
            except Exception:
                pass

    def check_for_updates(self, silent: bool = False):
        """GitHub Releases 기반 최신 업데이트 확인 및 적용"""
        from pathlib import Path
        from PyQt6.QtCore import QThread, pyqtSignal
        from PyQt6.QtWidgets import QProgressDialog
        from webshare_app.core.config import (
            UPDATE_MANIFEST_URL,
            UPDATE_PUBLIC_KEY_B64,
            UPDATE_RELEASES_URL,
        )
        from webshare_app.core.update_manifest import (
            NoUpdateAvailableError,
            download_release_manifest,
            verify_release_manifest,
        )
        from webshare_app.core.update_installer import (
            launch_update_helper,
            prepare_staged_update,
            resolve_update_staging_root,
            stream_update_artifact,
            update_result_path,
        )

        if getattr(self, "_update_in_progress", False):
            if not silent:
                QMessageBox.information(self, "업데이트", "이미 업데이트 확인 또는 다운로드가 진행 중입니다.")
            return

        self._update_in_progress = True

        progress = QProgressDialog("업데이트 정보를 확인하는 중...", "취소", 0, 0, self)
        progress.setWindowTitle("업데이트 확인")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.show()
        QApplication.processEvents()

        def cleanup_state():
            self._update_in_progress = False

        def do_check():
            try:
                manifest_bytes = download_release_manifest(UPDATE_MANIFEST_URL)
                manifest = verify_release_manifest(
                    manifest_bytes,
                    public_key=UPDATE_PUBLIC_KEY_B64,
                    current_version=APP_VERSION,
                )
                progress.close()

                # 새 버전 발견 알림 다이얼로그
                reply = QMessageBox.question(
                    self,
                    "새 버전 발견",
                    f"새로운 버전 WebShare Pro v{manifest.version}이(가) 출시되었습니다.\n\n"
                    f"현재 버전: v{APP_VERSION}\n"
                    f"새 버전: v{manifest.version}\n"
                    f"파일 크기: {manifest.artifact_size / 1024 / 1024:.1f} MB\n\n"
                    "지금 업데이트를 다운로드하고 적용하시겠습니까?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )

                if reply != QMessageBox.StandardButton.Yes:
                    cleanup_state()
                    return

                # 다운로드 진행 프로그레스 다이얼로그
                download_progress = QProgressDialog(
                    "새 버전 다운로드 중...",
                    "취소",
                    0,
                    manifest.artifact_size,
                    self,
                )
                download_progress.setWindowTitle("업데이트 다운로드")
                download_progress.setWindowModality(Qt.WindowModality.WindowModal)

                staging_root = resolve_update_staging_root()

                class UpdateDownloadWorker(QThread):
                    progress_signal = pyqtSignal(int, int)
                    finished_signal = pyqtSignal(object)
                    error_signal = pyqtSignal(str)

                    def __init__(self, manifest_obj, root_path):
                        super().__init__()
                        self.manifest = manifest_obj
                        self.root = root_path
                        self._is_canceled = False

                    def cancel(self):
                        self._is_canceled = True

                    def run(self):
                        try:
                            def chunk_gen():
                                downloaded = 0
                                for chunk in stream_update_artifact(self.manifest):
                                    if self._is_canceled:
                                        raise RuntimeError("사용자에 의해 다운로드가 취소되었습니다.")
                                    downloaded += len(chunk)
                                    self.progress_signal.emit(downloaded, self.manifest.artifact_size)
                                    yield chunk

                            staged_path = prepare_staged_update(
                                self.manifest,
                                chunks=chunk_gen(),
                                staging_root=self.root,
                                approve=lambda _m, _path: not self._is_canceled,
                            )
                            if self._is_canceled:
                                self.error_signal.emit("다운로드가 취소되었습니다.")
                            else:
                                self.finished_signal.emit(staged_path)
                        except Exception as worker_exc:
                            self.error_signal.emit(str(worker_exc))

                worker = UpdateDownloadWorker(manifest, staging_root)
                self._current_update_worker = worker

                def on_progress(current, total):
                    download_progress.setValue(current)

                def on_cancel():
                    worker.cancel()

                download_progress.canceled.connect(on_cancel)

                def on_finished(staged):
                    download_progress.close()
                    cleanup_state()
                    if not staged:
                        QMessageBox.warning(self, "취소됨", "업데이트 준비가 취소되었습니다.")
                        return

                    # 실행 파일 및 백업 경로 계산 (개발 모드 안전장치)
                    is_frozen = getattr(sys, "frozen", False)
                    if not is_frozen:
                        QMessageBox.information(
                            self,
                            "다운로드 완료 (개발 모드)",
                            f"새 버전 바이너리가 스테이징 폴더에 다운로드되었습니다:\n{staged}\n\n"
                            "현재 소스코드(개발 모드)로 실행 중이므로 자동 교체를 실행하지 않습니다.",
                        )
                        return

                    target_exe = Path(sys.executable).resolve()
                    backup_exe = target_exe.parent / f"{target_exe.name}.v{APP_VERSION}.bak"
                    result_file = update_result_path(staging_root)

                    # 헬퍼 프로세스 실행 후 현재 앱 종료
                    launch_update_helper(
                        target=target_exe,
                        staged=staged,
                        backup=backup_exe,
                        parent_pid=os.getpid(),
                        expected_sha256=manifest.artifact_sha256,
                        expected_size=manifest.artifact_size,
                        result_file=result_file,
                    )

                    QMessageBox.information(
                        self,
                        "재시작 중",
                        "업데이트를 적용하기 위해 프로그램을 재시작합니다.",
                    )
                    self.is_closing = True
                    QApplication.quit()

                def on_error(err_msg):
                    download_progress.close()
                    cleanup_state()
                    QMessageBox.critical(self, "다운로드 실패", f"업데이트 다운로드 중 오류가 발생했습니다:\n{err_msg}")

                worker.progress_signal.connect(on_progress)
                worker.finished_signal.connect(on_finished)
                worker.error_signal.connect(on_error)

                download_progress.show()
                worker.start()

            except NoUpdateAvailableError:
                progress.close()
                cleanup_state()
                if not silent:
                    QMessageBox.information(
                        self,
                        "최신 버전",
                        f"현재 최신 버전(v{APP_VERSION})을 사용 중입니다.",
                    )
            except Exception as exc:
                progress.close()
                cleanup_state()
                if not silent:
                    QMessageBox.critical(
                        self,
                        "업데이트 오류",
                        f"업데이트 확인 중 오류가 발생했습니다:\n{exc}",
                    )

        QTimer.singleShot(50, do_check)

