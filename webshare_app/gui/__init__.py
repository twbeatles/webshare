"""
WebShare Pro - GUI Package
PySide6 및 Tkinter GUI
"""

# GUI 사용 가능 여부 플래그
PYSIDE6_AVAILABLE = False
TKINTER_AVAILABLE = False

try:
    from PySide6.QtWidgets import QApplication
    PYSIDE6_AVAILABLE = True
except ImportError:
    pass

try:
    import tkinter as tk
    TKINTER_AVAILABLE = True
except ImportError:
    pass
