"""Compatibility alias for `webshare_app.utils.dashboard_service`."""

import sys as _sys
from importlib import import_module as _import_module

from webshare_app.utils.dashboard_service import *  # noqa: F401,F403

_module = _import_module("webshare_app.utils.dashboard_service")
_sys.modules[__name__] = _module
