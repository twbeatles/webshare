"""Compatibility package wrapper for `webshare_app.utils`."""

from importlib import import_module as _import_module

_TARGET = "webshare_app.utils"


def __getattr__(name):
    return getattr(_import_module(_TARGET), name)


def __dir__():
    return sorted(set(globals()) | set(dir(_import_module(_TARGET))))
