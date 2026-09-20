"""Server control and settings actions."""

from __future__ import annotations
# pyright: reportAttributeAccessIssue=false, reportArgumentType=false
import io
import os
import socket
import sys
import webbrowser
from PyQt6.QtWidgets import QApplication, QVBoxLayout, QLabel, QFileDialog, QMessageBox, QDialog
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap
from config import conf
from security.auth import hash_password
from server import get_server_startup_error, is_server_running, start_server, stop_server
from utils.log_manager import logger


class ServerActionsMixin:

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

