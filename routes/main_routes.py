"""Compatibility alias for `webshare_app.routes.main_routes`."""

from webshare_app.routes.main_routes import *  # noqa: F401,F403

import sys as _sys
from importlib import import_module as _import_module

_module = _import_module("webshare_app.routes.main_routes")
_sys.modules[__name__] = _module
