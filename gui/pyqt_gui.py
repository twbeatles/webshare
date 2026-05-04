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
DARK_STYLESHEET = """
QMainWindow, QWidget {
    background-color: #0f172a;
    color: #f1f5f9;
    font-family: 'Segoe UI', 'Malgun Gothic', sans-serif;
    font-size: 13px;
}

QTabWidget::pane {
    border: 1px solid #334155;
    border-radius: 12px;
    background-color: #1e293b;
    padding: 8px;
}

QTabBar::tab {
    background-color: transparent;
    color: #94a3b8;
    padding: 14px 28px;
    margin-right: 6px;
    border-top-left-radius: 10px;
    border-top-right-radius: 10px;
    font-weight: 500;
}

QTabBar::tab:selected {
    background-color: #334155;
    color: #f1f5f9;
    font-weight: 600;
}

QTabBar::tab:hover:!selected {
    background-color: rgba(51, 65, 85, 0.5);
    color: #e2e8f0;
}

QPushButton {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #6366f1, stop:1 #8b5cf6);
    color: white;
    border: none;
    padding: 14px 28px;
    border-radius: 12px;
    font-weight: 600;
    font-size: 13px;
}

QPushButton:hover {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #818cf8, stop:1 #a78bfa);
}

QPushButton:pressed {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #4f46e5, stop:1 #7c3aed);
}

QPushButton:disabled {
    background-color: #475569;
    color: #64748b;
}

QPushButton#stopBtn {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #ef4444, stop:1 #dc2626);
}

QPushButton#stopBtn:hover {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #f87171, stop:1 #ef4444);
}

QPushButton#outlineBtn {
    background-color: transparent;
    border: 2px solid #475569;
    color: #f1f5f9;
    border-radius: 12px;
}

QPushButton#outlineBtn:hover {
    background-color: rgba(51, 65, 85, 0.6);
    border-color: #818cf8;
}

QPushButton#outlineBtn:pressed {
    background-color: #334155;
}

QLineEdit, QComboBox {
    background-color: #1e293b;
    border: 2px solid #475569;
    border-radius: 10px;
    padding: 14px 16px;
    min-height: 22px;
    color: #f1f5f9;
    font-size: 13px;
    selection-background-color: #6366f1;
}

QComboBox {
    min-height: 24px;
    padding-right: 32px;
}

QComboBox QAbstractItemView {
    background-color: #1e293b;
    border: 1px solid #475569;
    border-radius: 8px;
    selection-background-color: #4f46e5;
    padding: 6px;
}

QLineEdit:focus, QComboBox:focus {
    border-color: #818cf8;
    background-color: #1e293b;
}

QLineEdit:hover, QComboBox:hover {
    border-color: #64748b;
}

QComboBox::drop-down {
    border: none;
    padding-right: 12px;
    width: 24px;
}

QTextEdit {
    background-color: #0f172a;
    border: 2px solid #334155;
    border-radius: 10px;
    padding: 12px;
    color: #94a3b8;
    font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    selection-background-color: #6366f1;
}

QTextEdit:focus {
    border-color: #475569;
}

QGroupBox {
    border: 2px solid #334155;
    border-radius: 12px;
    margin-top: 16px;
    padding: 20px 16px 16px 16px;
    font-weight: 600;
    color: #f1f5f9;
    background-color: rgba(30, 41, 59, 0.5);
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 16px;
    padding: 0 10px;
    color: #818cf8;
}

QCheckBox {
    color: #f1f5f9;
    spacing: 10px;
    font-size: 13px;
}

QCheckBox:hover {
    color: #e2e8f0;
}

QCheckBox::indicator {
    width: 20px;
    height: 20px;
    border-radius: 6px;
    border: 2px solid #475569;
    background-color: transparent;
}

QCheckBox::indicator:hover {
    border-color: #6366f1;
}

QCheckBox::indicator:checked {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #6366f1, stop:1 #8b5cf6);
    border-color: #6366f1;
}

QLabel {
    color: #f1f5f9;
    font-size: 13px;
}

QLabel#subtitle {
    color: #94a3b8;
    font-size: 12px;
    font-weight: 400;
}

QLabel#statusLabel {
    font-size: 20px;
    font-weight: 700;
}

QLabel#urlLabel {
    background-color: #1e293b;
    border: 2px solid #334155;
    border-radius: 12px;
    padding: 16px;
    font-family: 'Cascadia Code', 'Consolas', monospace;
    font-size: 15px;
    color: #818cf8;
}

QLabel#urlLabel:hover {
    border-color: #475569;
    background-color: rgba(30, 41, 59, 0.8);
}

QScrollArea {
    border: none;
    background-color: transparent;
}

QScrollBar:vertical {
    background-color: #1e293b;
    width: 12px;
    border-radius: 6px;
    margin: 4px 2px 4px 2px;
}

QScrollBar::handle:vertical {
    background-color: #475569;
    border-radius: 4px;
    min-height: 30px;
}

QScrollBar::handle:vertical:hover {
    background-color: #64748b;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background-color: #1e293b;
    height: 12px;
    border-radius: 6px;
    margin: 2px 4px 2px 4px;
}

QScrollBar::handle:horizontal {
    background-color: #475569;
    border-radius: 4px;
    min-width: 30px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #64748b;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
"""


class WebShareGUI(QMainWindow):
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


def run_pyqt6_gui():
    """PyQt6 GUI 실행"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = WebShareGUI()
    window.show()
    
    exit_code = app.exec()
    
    # 프로세스 완전 종료 보장
    sys.exit(exit_code)
