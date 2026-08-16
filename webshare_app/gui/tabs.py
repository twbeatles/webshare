from __future__ import annotations

# pyright: reportAttributeAccessIssue=false

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


class TabBuilderMixin:
    def init_ui(self):
            """UI 초기화"""
            central = QWidget()
            self.setCentralWidget(central)
            layout = QVBoxLayout(central)
            layout.setContentsMargins(20, 20, 20, 20)
            layout.setSpacing(0)

            # Header
            header = QHBoxLayout()
            title = QLabel("🚀 WebShare Pro")
            title.setStyleSheet("font-size: 24px; font-weight: bold; color: #818cf8;")
            header.addWidget(title)
            header.addStretch()

            update_btn = QPushButton("🔄 업데이트 확인")
            update_btn.setObjectName("outlineBtn")
            update_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            update_btn.clicked.connect(lambda: self.check_for_updates(silent=False))
            header.addWidget(update_btn)

            version = QLabel(f"v{APP_VERSION}")
            version.setObjectName("subtitle")
            header.addWidget(version)
            layout.addLayout(header)
            layout.addSpacing(20)

            # Tabs
            tabs = QTabWidget()
            tabs.addTab(self.build_home_tab(), "🏠 홈")
            tabs.addTab(self.build_settings_tab(), "⚙️ 설정")
            tabs.addTab(self.build_logs_tab(), "📝 로그")
            layout.addWidget(tabs)

    def build_home_tab(self):
            """홈 탭"""
            widget = QWidget()
            layout = QVBoxLayout(widget)
            layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.setSpacing(20)
            layout.setContentsMargins(40, 40, 40, 40)

            # Status indicator
            self.status_label = QLabel("⏹ 서버 중지됨")
            self.status_label.setObjectName("statusLabel")
            self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.status_label.setStyleSheet("color: #94a3b8;")
            layout.addWidget(self.status_label)

            layout.addSpacing(20)

            # Start/Stop button
            self.toggle_btn = QPushButton("▶  서버 시작")
            self.toggle_btn.setFixedHeight(60)
            self.toggle_btn.setStyleSheet("""
                QPushButton {
                    font-size: 16px;
                    font-weight: bold;
                }
            """)
            self.toggle_btn.clicked.connect(self.toggle_server)
            layout.addWidget(self.toggle_btn)

            layout.addSpacing(30)

            # Connection info
            info_group = QGroupBox(" 📡 접속 정보")
            info_layout = QVBoxLayout(info_group)

            self.url_label = QLabel("-")
            self.url_label.setObjectName("urlLabel")
            self.url_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.url_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            info_layout.addWidget(self.url_label)

            btn_layout = QHBoxLayout()

            browser_btn = QPushButton("🌐 브라우저 열기")
            browser_btn.setObjectName("outlineBtn")
            browser_btn.clicked.connect(self.open_browser)
            btn_layout.addWidget(browser_btn)

            qr_btn = QPushButton("📱 QR 코드")
            qr_btn.setObjectName("outlineBtn")
            qr_btn.clicked.connect(self.show_qr)
            btn_layout.addWidget(qr_btn)

            # 공유 폴더 열기 버튼
            folder_btn = QPushButton("📂 폴더 열기")
            folder_btn.setObjectName("outlineBtn")
            folder_btn.clicked.connect(self.open_shared_folder)
            btn_layout.addWidget(folder_btn)

            info_layout.addLayout(btn_layout)
            layout.addWidget(info_group)

            # 실시간 통계 패널
            stats_group = QGroupBox(" 📊 실시간 통계")
            stats_layout = QHBoxLayout(stats_group)

            self.stats_requests = QLabel("요청: 0")
            self.stats_requests.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.stats_requests.setStyleSheet("font-size: 13px; color: #818cf8; font-weight: bold;")
            stats_layout.addWidget(self.stats_requests)

            self.stats_connections = QLabel("접속: 0")
            self.stats_connections.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.stats_connections.setStyleSheet("font-size: 13px; color: #22c55e; font-weight: bold;")
            stats_layout.addWidget(self.stats_connections)

            self.stats_traffic = QLabel("트래픽: 0 B")
            self.stats_traffic.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.stats_traffic.setStyleSheet("font-size: 13px; color: #f59e0b; font-weight: bold;")
            stats_layout.addWidget(self.stats_traffic)

            layout.addWidget(stats_group)

            layout.addStretch()
            return widget

    def build_settings_tab(self):
            """설정 탭 - 스크롤 가능"""
            # QScrollArea로 감싸기
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            scroll.setStyleSheet("QScrollArea { border: none; background-color: transparent; }")

            widget = QWidget()
            scroll.setWidget(widget)

            layout = QVBoxLayout(widget)
            layout.setContentsMargins(30, 30, 30, 30)
            layout.setSpacing(15)

            # Folder settings
            folder_label = QLabel("📂 공유 폴더")
            layout.addWidget(folder_label)

            folder_layout = QHBoxLayout()
            self.folder_input = QLineEdit(conf.get('folder'))
            self.folder_input.setMinimumWidth(300)
            folder_layout.addWidget(self.folder_input)

            folder_btn = QPushButton("선택")
            folder_btn.setObjectName("outlineBtn")
            folder_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            folder_btn.setFixedWidth(80)
            folder_btn.clicked.connect(self.choose_folder)
            folder_layout.addWidget(folder_btn)
            layout.addLayout(folder_layout)

            layout.addSpacing(10)

            # Network settings
            net_label = QLabel("🌐 네트워크 (IP / Port)")
            layout.addWidget(net_label)

            net_layout = QHBoxLayout()
            self.ip_combo = QComboBox()
            ips = self.get_ip_list()
            self.ip_combo.addItems(ips)
            current = conf.get('display_host')
            if current in ips:
                self.ip_combo.setCurrentText(current)
            self.ip_combo.setMinimumWidth(200)
            net_layout.addWidget(self.ip_combo, 3)

            self.port_input = QLineEdit(str(conf.get('port')))
            self.port_input.setFixedWidth(80)
            self.port_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
            net_layout.addWidget(self.port_input, 1)
            layout.addLayout(net_layout)

            layout.addSpacing(10)

            # Password settings
            pw_label = QLabel("🔐 비밀번호 (관리자 / 게스트)")
            layout.addWidget(pw_label)

            pw_layout = QHBoxLayout()
            self.admin_pw = QLineEdit("")
            self.admin_pw.setEchoMode(QLineEdit.EchoMode.Password)
            self.admin_pw.setPlaceholderText("관리자 암호 변경 시 입력")
            pw_layout.addWidget(self.admin_pw)

            self.guest_pw = QLineEdit("")
            self.guest_pw.setEchoMode(QLineEdit.EchoMode.Password)
            self.guest_pw.setPlaceholderText("게스트 암호 변경 시 입력")
            pw_layout.addWidget(self.guest_pw)
            layout.addLayout(pw_layout)

            layout.addSpacing(15)

            # Checkboxes Group
            group_box = QGroupBox("기본 설정")
            group_layout = QVBoxLayout()

            self.guest_upload_check = QCheckBox("게스트 업로드 허용")
            self.guest_upload_check.setChecked(conf.get('allow_guest_upload', False))
            group_layout.addWidget(self.guest_upload_check)

            self.https_check = QCheckBox("HTTPS 사용 (자체 서명 인증서)")
            self.https_check.setChecked(conf.get('use_https', False))
            group_layout.addWidget(self.https_check)

            group_box.setLayout(group_layout)
            layout.addWidget(group_box)

            layout.addSpacing(10)

            # Advanced Settings Group
            adv_group = QGroupBox("🔧 고급 설정")
            adv_layout = QVBoxLayout()

            self.versioning_check = QCheckBox("파일 버전 관리 활성화")
            self.versioning_check.setChecked(conf.get('enable_versioning', True))
            adv_layout.addWidget(self.versioning_check)

            self.notification_check = QCheckBox("시스템 알림 활성화")
            self.notification_check.setChecked(conf.get('enable_notifications', True))
            adv_layout.addWidget(self.notification_check)

            # Tray options
            self.tray_check = QCheckBox("최소화 버튼 시 트레이로 이동")
            self.tray_check.setChecked(conf.get('minimize_to_tray', True))
            adv_layout.addWidget(self.tray_check)

            self.close_tray_check = QCheckBox("닫기(X) 버튼 시 트레이로 이동")
            self.close_tray_check.setChecked(conf.get('close_to_tray', True))
            adv_layout.addWidget(self.close_tray_check)

            self.autostart_check = QCheckBox("윈도우 시작 시 자동 실행")
            self.autostart_check.setChecked(conf.get('autostart', False))
            adv_layout.addWidget(self.autostart_check)

            # Session Timeout
            timeout_layout = QHBoxLayout()
            timeout_label = QLabel("세션 타임아웃 (분):")
            timeout_layout.addWidget(timeout_label)
            self.timeout_input = QLineEdit(str(conf.get('session_timeout', 30)))
            self.timeout_input.setFixedWidth(80)
            self.timeout_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
            timeout_layout.addWidget(self.timeout_input)
            timeout_layout.addStretch()
            adv_layout.addLayout(timeout_layout)

            adv_group.setLayout(adv_layout)
            layout.addWidget(adv_group)

            layout.addSpacing(20)

            # Save button container
            btn_layout = QHBoxLayout()
            btn_layout.addStretch()
            save_btn = QPushButton("💾 설정 저장")
            save_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            save_btn.setFixedWidth(120)
            save_btn.setFixedHeight(40)
            save_btn.clicked.connect(self.save_settings)
            btn_layout.addWidget(save_btn)
            btn_layout.addStretch()
            layout.addLayout(btn_layout)

            layout.addStretch()

            return scroll

    def build_logs_tab(self):
            """로그 탭 - 필터링 및 내보내기 기능"""
            widget = QWidget()
            layout = QVBoxLayout(widget)
            layout.setContentsMargins(20, 20, 20, 20)

            # 필터 및 도구 바
            toolbar = QHBoxLayout()

            filter_label = QLabel("필터:")
            toolbar.addWidget(filter_label)

            self.log_filter = QComboBox()
            self.log_filter.addItems(["전체", "INFO", "WARN", "ERROR"])
            self.log_filter.currentTextChanged.connect(self.filter_logs)
            self.log_filter.setFixedWidth(100)
            toolbar.addWidget(self.log_filter)

            toolbar.addStretch()

            export_btn = QPushButton("📄 내보내기")
            export_btn.setObjectName("outlineBtn")
            export_btn.clicked.connect(self.export_logs)
            toolbar.addWidget(export_btn)

            layout.addLayout(toolbar)

            self.log_text = QTextEdit()
            self.log_text.setReadOnly(True)
            self.log_text.setPlaceholderText("서버 로그가 여기에 표시됩니다...")
            layout.addWidget(self.log_text)

            btn_layout = QHBoxLayout()

            clear_btn = QPushButton("🗑 로그 클리어")
            clear_btn.setObjectName("outlineBtn")
            clear_btn.clicked.connect(self.clear_logs)
            btn_layout.addWidget(clear_btn)

            layout.addLayout(btn_layout)

            return widget
