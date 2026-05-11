"""Compatibility alias for `webshare_app.utils.listing`."""

from webshare_app.utils.listing import *  # noqa: F401,F403

import sys as _sys
from importlib import import_module as _import_module

_module = _import_module("webshare_app.utils.listing")
_sys.modules[__name__] = _module
