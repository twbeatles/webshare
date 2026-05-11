"""Compatibility alias for `webshare_app.utils.file_utils`."""

from webshare_app.utils.file_utils import *  # noqa: F401,F403

import sys as _sys
from importlib import import_module as _import_module

_module = _import_module("webshare_app.utils.file_utils")
_sys.modules[__name__] = _module
