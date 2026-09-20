"""Composed TabBuilderMixin with shell init."""

from __future__ import annotations
# pyright: reportAttributeAccessIssue=false
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTabWidget
from PyQt6.QtCore import Qt
from config import APP_VERSION
from .home_tab import HomeTabMixin
from .settings_tab import SettingsTabMixin
from .logs_tab import LogsTabMixin


class TabBuilderMixin(HomeTabMixin, SettingsTabMixin, LogsTabMixin):
    """Composed tab builder (behavior unchanged; see per-tab mixins)."""
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
