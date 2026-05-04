"""Application-level filesystem paths and atomic JSON helpers."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def get_app_config_dir(app_name: str = "WebSharePro") -> str:
    """Return an app-owned config directory outside the shared folder."""
    override = os.environ.get("WEBSHARE_CONFIG_DIR")
    if override:
        return override
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return os.path.join(base, app_name)

    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return os.path.join(base, app_name.lower())


def atomic_write_json(path: str, payload: Any):
    """Write JSON atomically in the target directory."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".webshare_write_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        os.replace(temp_path, path)
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise
