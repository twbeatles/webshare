"""Compatibility alias for `webshare_app.features.cloud_sync`."""

from webshare_app.features.cloud_sync import *  # noqa: F401,F403

import sys as _sys
from importlib import import_module as _import_module

_module = _import_module("webshare_app.features.cloud_sync")
_sys.modules[__name__] = _module
