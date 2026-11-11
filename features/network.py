"""Compatibility alias for `webshare_app.features.network`."""

import sys as _sys
from importlib import import_module as _import_module

from webshare_app.features.network import *  # noqa: F401,F403

_module = _import_module("webshare_app.features.network")
_sys.modules[__name__] = _module
