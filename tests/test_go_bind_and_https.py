"""Regression tests for PROJECT_AUDIT ISSUE-001 and ISSUE-002.

ISSUE-001: the Go backend must bind ``conf.display_host`` (LAN/0.0.0.0),
not a hardcoded 127.0.0.1, while readiness/control probes stay loopback.
ISSUE-002: the use_https+Go combination must be refused with a clear error
(never plain HTTP with Secure cookies).

Hermetic: never spawns a real server, never touches user files.
"""

import subprocess

import pytest

import webshare_app.server as srv
from config import conf
from webshare_app.server import go_process
from webshare_app.server.go_process import GoServerProcess


class _CapturingGo:
    """Fake Go singleton recording start() kwargs."""

    bound_host: str = ""
    bound_port: int = 0

    def __init__(self):
        self.kwargs = None
        self.startup_error = ""

    def start(self, **kwargs):
        self.kwargs = kwargs
        return True

    def is_alive(self):
        return True


@pytest.fixture
def _conf_snapshot():
    saved = {
        "display_host": conf.get("display_host"),
        "use_https": conf.get("use_https"),
    }
    yield
    conf.set("display_host", saved["display_host"])
    conf.set("use_https", saved["use_https"])


@pytest.mark.parametrize("display_host", ["0.0.0.0", "192.168.0.15"])
def test_start_server_passes_display_host_to_go(monkeypatch, _conf_snapshot, display_host):
    """ISSUE-001: conf.display_host reaches the Go child as --host."""
    fake = _CapturingGo()
    monkeypatch.setattr(srv, "_use_go_backend", lambda: True)
    monkeypatch.setattr(srv, "_go_singleton", lambda: fake)
    conf.set("display_host", display_host)
    conf.set("use_https", False)
    assert srv.start_server() is True
    assert fake.kwargs is not None
    assert fake.kwargs["host"] == display_host


def test_start_server_blocks_https_on_go(monkeypatch, _conf_snapshot):
    """ISSUE-002: use_https+Go refuses to start with a clear error."""
    fake = _CapturingGo()
    monkeypatch.setattr(srv, "_use_go_backend", lambda: True)
    monkeypatch.setattr(srv, "_go_singleton", lambda: fake)
    calls = []
    monkeypatch.setattr(
        srv, "_start_python_thread", lambda *a, **k: calls.append((a, k)) or True
    )
    conf.set("display_host", "0.0.0.0")

    # Explicit argument blocks.
    conf.set("use_https", False)
    assert srv.start_server(use_https=True) is False
    # Config value blocks too (GUI passes conf through use_https anyway).
    conf.set("use_https", True)
    assert srv.start_server() is False

    assert fake.kwargs is None  # Go child never spawned
    assert calls == []  # no silent plain-HTTP fallback either
    err = srv.get_server_startup_error()
    assert "HTTPS" in err
    assert "python" in err.lower()


class _FakePopen:
    """Minimal Popen stub capturing argv; never spawns a process."""

    def __init__(self, cmd, **kwargs):
        self.cmd = cmd
        self.stdout = []  # drain thread iterates zero lines and exits

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 0

    def terminate(self):
        pass

    def kill(self):
        pass


def test_go_process_keeps_loopback_probe_on_lan_bind(monkeypatch, tmp_path):
    """ISSUE-001: LAN bind still probes/shuts down via loopback."""
    monkeypatch.setenv(go_process.BINARY_ENV, str(tmp_path / "webshare-core.exe"))
    (tmp_path / "webshare-core.exe").write_bytes(b"fake")
    captured = {}
    real_popen = subprocess.Popen

    def fake_popen(cmd, **kwargs):
        proc = _FakePopen(cmd, **kwargs)
        captured["cmd"] = cmd
        return proc

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(GoServerProcess, "_wait_ready", lambda self, timeout: True)
    proc = GoServerProcess()
    try:
        assert proc.start(host="0.0.0.0", port=51234, timeout=1.0) is True
        cmd = captured["cmd"]
        assert "--host" in cmd
        assert cmd[cmd.index("--host") + 1] == "0.0.0.0"
        # Readiness/control plane stays loopback even on a LAN bind.
        assert proc.base_url == "http://127.0.0.1:51234"
        assert proc.bind_address() == ("0.0.0.0", 51234)
    finally:
        proc.proc = None
    assert real_popen is not None


def test_get_server_bind_info_reports_go_address(monkeypatch):
    """GUI helper surfaces the actual Go bind address (ISSUE-001)."""
    fake = _CapturingGo()
    fake.bound_host = "0.0.0.0"
    fake.bound_port = 5000
    monkeypatch.setattr(srv, "_go_singleton", lambda: fake)
    info = srv.get_server_bind_info()
    assert info == {"backend": "go", "host": "0.0.0.0", "port": 5000, "proto": "http"}
