"""Compatibility alias for `webshare_app.routes.share_routes`."""

from webshare_app.routes.share_routes import *  # noqa: F401,F403
from webshare_app.routes.share_routes import _share_password_attempts, _share_password_attempts_lock  # noqa: F401

import sys as _sys
from importlib import import_module as _import_module

_module = _import_module("webshare_app.routes.share_routes")
_sys.modules[__name__] = _module
