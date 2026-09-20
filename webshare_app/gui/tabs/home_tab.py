"""Home tab construction."""

from __future__ import annotations
# pyright: reportAttributeAccessIssue=false
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QGroupBox
from PyQt6.QtCore import Qt


class HomeTabMixin:

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

