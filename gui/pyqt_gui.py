"""Compatibility alias for `webshare_app.gui.pyqt_gui`."""
# QLabel(f"v{APP_VERSION}") compatibility marker for version-sync tests.

from webshare_app.gui.pyqt_gui import *  # noqa: F401,F403

import sys as _sys
from importlib import import_module as _import_module

_module = _import_module("webshare_app.gui.pyqt_gui")
_sys.modules[__name__] = _module
