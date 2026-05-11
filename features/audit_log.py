"""Compatibility alias for `webshare_app.features.audit_log`."""

from webshare_app.features.audit_log import *  # noqa: F401,F403

import sys as _sys
from importlib import import_module as _import_module

_module = _import_module("webshare_app.features.audit_log")
_sys.modules[__name__] = _module
