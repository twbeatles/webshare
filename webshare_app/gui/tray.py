from __future__ import annotations

# pyright: reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false

import io
import os
import socket
import webbrowser

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QComboBox, QCheckBox, QTabWidget,
    QTextEdit, QFileDialog, QMessageBox, QGroupBox, QSystemTrayIcon, QMenu,
    QScrollArea, QDialog,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QAction, QPixmap

from config import APP_TITLE, APP_VERSION, MAX_LOG_LINES, STATS, conf
from security.auth import hash_password
from server import get_server_startup_error, is_server_running, start_server, stop_server
from utils.log_manager import logger


class TrayMixin:
    def setup_tray(self):
            """시스템 트레이 아이콘 설정"""
            self.tray_icon = QSystemTrayIcon(self)
            self.tray_icon.setToolTip(APP_TITLE)

            # 트레이 메뉴
            tray_menu = QMenu()

            show_action = QAction("프로그램 열기", self)
            show_action.triggered.connect(self.show_normal)
            tray_menu.addAction(show_action)

            browser_action = QAction("브라우저로 열기", self)
            browser_action.triggered.connect(self.open_browser)
            tray_menu.addAction(browser_action)

            tray_menu.addSeparator()

            quit_action = QAction("완전 종료", self)
            quit_action.triggered.connect(self.force_quit)
            tray_menu.addAction(quit_action)

            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.activated.connect(self.tray_activated)
            self.tray_icon.show()

    def tray_activated(self, reason):
            if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
                self.show_normal()

    def show_normal(self):
            self.show()
            self.activateWindow()

    def force_quit(self):
            """완전 종료 (트레이에서 호출)"""
            self.is_closing = True
            self._cleanup_and_exit()

    def show_notification(self, title, message):
            """시스템 알림 표시"""
            if conf.get('enable_notifications') and self.tray_icon.isVisible():
                self.tray_icon.showMessage(title, message, QSystemTrayIcon.MessageIcon.Information, 3000)

    def closeEvent(self, a0):
            """창 닫기 이벤트"""
            if a0 is None:
                return
            event = a0
            # 완전 종료 시 트레이 로직 우회
            if self.is_closing:
                event.accept()
                return

            # 서버 실행 중이면 트레이로 최소화 (설정에 따라)
            should_minimize = False
            if conf.get('close_to_tray'):  # 항상 최소화
                should_minimize = True
            elif is_server_running() and conf.get('minimize_to_tray'):  # 서버 실행 중일 때만
                should_minimize = True

            if should_minimize:
                event.ignore()
                self.hide()
                if conf.get('enable_notifications'):
                    self.tray_icon.showMessage(
                        "WebShare Pro",
                        "서버가 백그라운드에서 계속 실행 중입니다.",
                        QSystemTrayIcon.MessageIcon.Information,
                        2000
                    )
                return

            self.is_closing = True
            if is_server_running():
                reply = QMessageBox.question(self, "종료", "서버가 실행 중입니다. 종료하시겠습니까?",
                                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.Yes:
                    self._cleanup_and_exit()
                    event.accept()
                else:
                    self.is_closing = False
                    event.ignore()
            else:
                self._cleanup_and_exit()
                event.accept()

    def _cleanup_and_exit(self):
            """종료 전 정리 작업"""
            # 타이머 중지
            if hasattr(self, 'log_timer'):
                self.log_timer.stop()
            if hasattr(self, 'stats_timer'):
                self.stats_timer.stop()

            # 서버 종료
            stop_server()

            # 트레이 아이콘 숨기기
            if hasattr(self, 'tray_icon'):
                self.tray_icon.hide()
