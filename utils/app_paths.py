"""Compatibility alias for `webshare_app.core.app_paths`."""

from webshare_app.core.app_paths import *  # noqa: F401,F403

import sys as _sys
from importlib import import_module as _import_module

_module = _import_module("webshare_app.core.app_paths")
_sys.modules[__name__] = _module
