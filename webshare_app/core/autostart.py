"""Windows login autostart (HKCU Run key) for the desktop app.

The settings checkbox "윈도우 시작 시 자동 실행" used to be stored in config
without any effect. This module registers/unregisters the app under
``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run``. A Run-key launch
starts in an arbitrary working directory, while config and the default shared
folder are CWD-relative, so the command pins ``--workdir``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "WebSharePro"


def is_supported() -> bool:
    return sys.platform == "win32"


def _winreg():
    import winreg  # Windows-only stdlib module; resolved lazily for tests

    return winreg


def build_command(workdir: str | None = None) -> str:
    """Command line registered for login autostart."""
    workdir = os.path.abspath(workdir or os.getcwd())
    if getattr(sys, "frozen", False):
        parts = [sys.executable]
    else:
        interpreter = Path(sys.executable)
        windowed = interpreter.with_name("pythonw.exe")
        if windowed.is_file():
            interpreter = windowed
        main_script = Path(__file__).resolve().parents[2] / "main.py"
        parts = [str(interpreter), str(main_script)]
    parts += ["--workdir", workdir]
    return subprocess.list2cmdline(parts)


def is_enabled() -> bool:
    if not is_supported():
        return False
    winreg = _winreg()
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, VALUE_NAME)
        return True
    except OSError:
        return False


def set_enabled(enabled: bool, workdir: str | None = None) -> tuple[bool, str]:
    """Register (enabled) or remove the autostart entry. Returns (ok, error)."""
    if not is_supported():
        return False, "자동 실행은 Windows에서만 지원됩니다."
    winreg = _winreg()
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, build_command(workdir))
            else:
                try:
                    winreg.DeleteValue(key, VALUE_NAME)
                except FileNotFoundError:
                    pass
        return True, ""
    except OSError as exc:
        return False, f"자동 실행 설정 실패: {exc}"
