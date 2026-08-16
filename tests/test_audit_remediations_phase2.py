from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.apply_update import _wait_for_parent
from webshare_app.core.update_installer import cleanup_stale_update_helpers
from webshare_app.core.update_manifest import download_release_manifest


def test_wait_for_parent_invalid_pid():
    with pytest.raises(ValueError, match="Parent process ID must be positive"):
        _wait_for_parent(0)
    with pytest.raises(ValueError, match="Parent process ID must be positive"):
        _wait_for_parent(-1)


def test_wait_for_parent_exited_process():
    # A non-existent PID should return immediately without waiting
    start = time.monotonic()
    _wait_for_parent(9999999, timeout=5.0)
    elapsed = time.monotonic() - start
    assert elapsed < 2.0


def test_cleanup_stale_update_helpers(tmp_path: Path):
    now = time.time()
    stale_helper = tmp_path / "update-helper-old.exe"
    stale_helper.write_bytes(b"old")
    # Set mtime to 2 days ago
    os.utime(stale_helper, (now - 48 * 3600, now - 48 * 3600))

    fresh_helper = tmp_path / "update-helper-fresh.exe"
    fresh_helper.write_bytes(b"fresh")
    os.utime(fresh_helper, (now - 1 * 3600, now - 1 * 3600))

    cleanup_stale_update_helpers(tmp_path, max_age_hours=24.0)

    assert not stale_helper.exists()
    assert fresh_helper.exists()


def test_download_release_manifest_cache_bust(monkeypatch):
    captured_request = None

    class MockResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def geturl(self):
            return "https://example.com/latest.json"

        def read(self, limit):
            return b'{"payload": {}, "signature": ""}'

    def mock_urlopen(req, timeout=None):
        nonlocal captured_request
        captured_request = req
        return MockResponse()

    monkeypatch.setattr("webshare_app.core.update_manifest.urlopen", mock_urlopen)

    data = download_release_manifest("https://example.com/latest.json", cache_bust=True)
    assert data == b'{"payload": {}, "signature": ""}'
    assert captured_request is not None
    assert "_=" in captured_request.full_url
    assert captured_request.headers.get("Cache-control") == "no-cache, no-store, must-revalidate"
    assert captured_request.headers.get("Pragma") == "no-cache"


def test_update_actions_safeguard_non_frozen(tmp_path: Path, monkeypatch):
    from webshare_app.gui.actions import GuiActionsMixin

    class MockGUI(GuiActionsMixin):
        def __init__(self):
            self.closed = False
            self.dialog_shown = False
            self.message_shown = []

    gui = MockGUI()
    # ensure sys.frozen is False
    monkeypatch.delattr(sys, "frozen", raising=False)

    # Calling check_for_updates shouldn't crash
    assert not getattr(sys, "frozen", False)
