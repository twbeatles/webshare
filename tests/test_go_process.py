"""Go backend launcher tests (migration plan Phase 2).

Hermetic: never spawns a real server, never touches user files.
"""

import os

import pytest

from webshare_app.server import go_process
from webshare_app.server.go_process import GoServerProcess, find_binary, generate_control_token


def test_backend_defaults_to_go(monkeypatch):
    """Milestone J: Go is the default backend."""
    monkeypatch.delenv(go_process.BACKEND_ENV, raising=False)
    assert go_process.backend_name() == "go"


def test_backend_env_selects_python(monkeypatch):
    """WEBSHARE_SERVER_BACKEND=python keeps the legacy Python backend."""
    monkeypatch.setenv(go_process.BACKEND_ENV, "python")
    assert go_process.backend_name() == "python"


def test_control_tokens_unique_and_256bit():
    a, b = generate_control_token(), generate_control_token()
    assert a != b
    assert len(a) == 64 and len(b) == 64
    int(a, 16)


def test_find_binary_respects_override_missing(monkeypatch, tmp_path):
    monkeypatch.setenv(go_process.BINARY_ENV, str(tmp_path / "nope.exe"))
    assert find_binary() is None


def test_find_binary_respects_override_present(monkeypatch, tmp_path):
    fake = tmp_path / "webshare-core.exe"
    fake.write_bytes(b"fake")
    monkeypatch.setenv(go_process.BINARY_ENV, str(fake))
    assert find_binary() == str(fake)


def test_start_fails_cleanly_without_binary(monkeypatch, tmp_path):
    monkeypatch.setenv(go_process.BINARY_ENV, str(tmp_path / "nope.exe"))
    proc = GoServerProcess()
    assert proc.start(port=50199, timeout=1.0) is False
    assert "바이너리" in proc.startup_error
    assert not proc.is_alive()


def test_shutdown_without_start_is_noop():
    assert GoServerProcess().shutdown() is False


def test_go_backend_selected_by_default(monkeypatch):
    """Milestone J: default backend routes to Go; python is explicit opt-out."""
    import webshare_app.server as srv

    monkeypatch.delenv(go_process.BACKEND_ENV, raising=False)
    assert srv._use_go_backend() is True
    assert srv.is_server_running() is False
    monkeypatch.setenv(go_process.BACKEND_ENV, "python")
    assert srv._use_go_backend() is False


def test_go_failure_falls_back_to_python(monkeypatch):
    """Milestone J / plan section 58: Go failure starts the Python backend."""
    import webshare_app.server as srv

    monkeypatch.delenv(go_process.BACKEND_ENV, raising=False)
    monkeypatch.setattr(srv, "_go_singleton", lambda: _FailingGo())
    calls = []
    monkeypatch.setattr(srv, "_start_python_thread",
                        lambda *a, **k: calls.append((a, k)) or True)
    assert srv.start_server() is True
    assert len(calls) == 1


class _FailingGo:
    startup_error = "boom"

    def start(self, **kwargs):
        return False
