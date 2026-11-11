"""Compatibility alias for `webshare_app.routes.share_routes`."""

import sys as _sys
from importlib import import_module as _import_module

from webshare_app.routes.share_routes import *  # noqa: F401,F403
from webshare_app.routes.share_routes import (  # noqa: F401
    _share_password_attempts,
    _share_password_attempts_lock,
)

_module = _import_module("webshare_app.routes.share_routes")
_sys.modules[__name__] = _module
