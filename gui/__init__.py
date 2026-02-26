"""
WebShare Pro - GUI Package
PyQt6 및 Tkinter GUI
"""

# GUI 사용 가능 여부 플래그
PYQT6_AVAILABLE = False
TKINTER_AVAILABLE = False

try:
    from PyQt6.QtWidgets import QApplication
    PYQT6_AVAILABLE = True
except ImportError:
    pass

try:
    import tkinter as tk
    TKINTER_AVAILABLE = True
except ImportError:
    pass
