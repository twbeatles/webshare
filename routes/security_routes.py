"""Compatibility alias for `webshare_app.routes.security_routes`."""

import sys as _sys
from importlib import import_module as _import_module

from webshare_app.routes.security_routes import *  # noqa: F401,F403

_module = _import_module("webshare_app.routes.security_routes")
_sys.modules[__name__] = _module
