"""Compatibility package wrapper for `webshare_app.routes`."""

from importlib import import_module as _import_module

_TARGET = "webshare_app.routes"


def __getattr__(name):
    return getattr(_import_module(_TARGET), name)


def __dir__():
    return sorted(set(globals()) | set(dir(_import_module(_TARGET))))



def register_routes(app):
    return _import_module(_TARGET).register_routes(app)
