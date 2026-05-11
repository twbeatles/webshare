"""
WebShare Pro - PyQt6 GUI
메인 GUI 윈도우 (전체 기능 복구 버전)
"""

import os
import sys
import socket
import webbrowser
import io

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QComboBox, QCheckBox, QTabWidget,
    QTextEdit, QFileDialog, QMessageBox, QGroupBox, QSystemTrayIcon, QMenu,
    QScrollArea, QDialog
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QAction, QPixmap

from config import conf, APP_TITLE, APP_VERSION, STATS, MAX_LOG_LINES
from security.auth import hash_password
from utils.log_manager import logger
from server import get_server_startup_error, start_server, stop_server, is_server_running


# 다크 테마 스타일시트
from webshare_app.gui.actions import GuiActionsMixin
from webshare_app.gui.styles import DARK_STYLESHEET
from webshare_app.gui.tabs import TabBuilderMixin
from webshare_app.gui.tray import TrayMixin


class WebShareGUI(TrayMixin, TabBuilderMixin, GuiActionsMixin, QMainWindow):
    """WebShare Pro 메인 GUI 윈도우"""

    server_update_signal = pyqtSignal(bool)

    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)

        # HiDPI 지원: 스케일링된 창 크기
        base_w, base_h = 650, 700
        self.setMinimumSize(base_w, base_h)
        self.resize(base_w, base_h + 50)
        self.setStyleSheet(DARK_STYLESHEET)

        self.is_closing = False

        # 로그 타이머
        self.log_timer = QTimer()
        self.log_timer.timeout.connect(self.process_logs)
        self.log_timer.start(200)

        # 시그널 연결
        self.server_update_signal.connect(self.update_ui_state)

        # 실시간 통계 타이머
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats)
        self.stats_timer.start(5000)  # 5초마다 업데이트

        # 시스템 트레이 설정
        self.setup_tray()

        # 로그 저장용 리스트
        self.all_logs = []

        # UI 초기화
        self.init_ui()



























def run_pyqt6_gui():
    """PyQt6 GUI 실행"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    window = WebShareGUI()
    window.show()

    exit_code = app.exec()

    # 프로세스 완전 종료 보장
    sys.exit(exit_code)
