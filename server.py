"""Compatibility alias for `webshare_app.server`."""

from webshare_app.server import *  # noqa: F401,F403
from webshare_app.server import _runtime_initialized  # noqa: F401

import sys as _sys
from importlib import import_module as _import_module

_module = _import_module("webshare_app.server")
_sys.modules[__name__] = _module
