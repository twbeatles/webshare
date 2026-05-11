"""Qt stylesheets for the desktop GUI."""

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
