"""Compatibility alias for `webshare_app.features.job_store`."""

from webshare_app.features.job_store import *  # noqa: F401,F403

import sys as _sys
from importlib import import_module as _import_module

_module = _import_module("webshare_app.features.job_store")
_sys.modules[__name__] = _module
