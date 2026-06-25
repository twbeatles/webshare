"""Serialized JSON persistence helpers (snapshot + write under one file lock)."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any, TypeVar

from webshare_app.core.app_paths import atomic_write_json

T = TypeVar("T")

_registry_guard = threading.Lock()
_file_locks: dict[str, threading.Lock] = {}


def _lock_for(persist_key: str) -> threading.Lock:
    with _registry_guard:
        lock = _file_locks.get(persist_key)
        if lock is None:
            lock = threading.Lock()
            _file_locks[persist_key] = lock
        return lock


def persist_json_snapshot(
    persist_key: str,
    path: str,
    data_lock: threading.Lock,
    build_payload: Callable[[], T],
) -> bool:
    """
    Build a payload while holding ``data_lock``, then write atomically.

    A per-``persist_key`` lock serializes writers so an older snapshot cannot
    overwrite a newer one after a concurrent save finishes.
    """
    file_lock = _lock_for(persist_key)
    with file_lock:
        with data_lock:
            payload = build_payload()
        atomic_write_json(path, payload)
    return True


def persist_json_value(persist_key: str, path: str, payload: Any) -> bool:
    """Persist a pre-built payload (caller already synchronized)."""
    file_lock = _lock_for(persist_key)
    with file_lock:
        atomic_write_json(path, payload)
    return True