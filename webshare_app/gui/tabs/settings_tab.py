"""Settings tab construction."""

from __future__ import annotations
# pyright: reportAttributeAccessIssue=false
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit, QComboBox, QCheckBox, QGroupBox, QScrollArea
from PyQt6.QtCore import Qt
from config import conf


class SettingsTabMixin:

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

