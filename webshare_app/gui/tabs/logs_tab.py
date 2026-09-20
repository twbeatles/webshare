"""Logs tab construction."""

from __future__ import annotations
# pyright: reportAttributeAccessIssue=false
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QComboBox, QTextEdit


class LogsTabMixin:

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

