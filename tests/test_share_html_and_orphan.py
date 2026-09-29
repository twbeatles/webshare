"""Regression tests for PROJECT_AUDIT ISSUE-003 and ISSUE-005.

ISSUE-003: when the Go child dies while its port stays occupied (stale
orphan from a crashed GUI run), ``GoServerProcess.startup_error`` must name
the orphan instead of reporting a bare timeout.
ISSUE-005: the Python share-access contract browsers rely on — password
form (200 ``text/html``), wrong-password re-render (200), expired/missing
links (``text/html`` pages).

Hermetic: never spawns a real server, never touches user files.
"""

import socket
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from config import SHARE_LINKS, conf, share_links_lock
from webshare_app.security.auth import hash_password
from webshare_app.server import go_process
from webshare_app.server.go_process import GoServerProcess


# -- ISSUE-003: stale-orphan port-conflict diagnostics --------------------


class _StubPopen:
    """Minimal Popen stub; ``exit_code=None`` means still running."""

    def __init__(self, cmd, exit_code=1, **kwargs):
        self.cmd = cmd
        self.stdout = []
        self._exit_code = exit_code

    def poll(self):
        return self._exit_code

    def wait(self, timeout=None):
        return self._exit_code or 0

    def terminate(self):
        pass

    def kill(self):
        pass


def _hermetic_start(monkeypatch, tmp_path, exit_code):
    """Point the launcher at a fake binary + stub Popen + failed readiness."""
    fake = tmp_path / "webshare-core.exe"
    fake.write_bytes(b"fake")
    monkeypatch.setenv(go_process.BINARY_ENV, str(fake))
    monkeypatch.setattr(
        subprocess, "Popen", lambda cmd, **kw: _StubPopen(cmd, exit_code))
    monkeypatch.setattr(
        GoServerProcess, "_wait_ready", lambda self, timeout: False)


def _occupied_port():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    return srv, srv.getsockname()[1]


def test_orphan_hint_when_child_dead_and_port_occupied(
        monkeypatch, tmp_path):
    """ISSUE-003: dead child + live port => startup_error names the orphan."""
    _hermetic_start(monkeypatch, tmp_path, exit_code=1)
    holder, port = _occupied_port()
    try:
        proc = GoServerProcess()
        assert proc.start(port=port, timeout=0.1) is False
    finally:
        holder.close()
    assert "고아" in proc.startup_error
    assert str(port) in proc.startup_error


def test_no_orphan_hint_when_port_free(monkeypatch, tmp_path):
    """ISSUE-003: dead child + free port => plain startup error, no hint."""
    _hermetic_start(monkeypatch, tmp_path, exit_code=1)
    holder, port = _occupied_port()
    holder.close()  # release: nothing answers now
    proc = GoServerProcess()
    assert proc.start(port=port, timeout=0.1) is False
    assert "고아" not in proc.startup_error


def test_no_orphan_hint_when_child_alive_but_unready(
        monkeypatch, tmp_path):
    """ISSUE-003: the port is ours while our own child lives — no hint."""
    _hermetic_start(monkeypatch, tmp_path, exit_code=None)
    holder, port = _occupied_port()
    proc = GoServerProcess()
    try:
        assert proc.start(port=port, timeout=0.1) is False
    finally:
        holder.close()
        proc.proc = None
    assert "고아" not in proc.startup_error


def test_orphan_hint_helper_only_fires_on_occupied_port():
    holder, port = _occupied_port()
    try:
        assert "고아" in go_process.orphan_hint_for(port)
    finally:
        holder.close()
    assert go_process.orphan_hint_for(port) == ""


# -- ISSUE-005: Python share-access HTML contract --------------------------


def _put_share(token, **fields):
    info = {
        "path": "hello.txt",
        "expires": datetime.now() + timedelta(hours=1),
        "created_by": "admin",
        "is_dir": False,
        "password_hash": None,
        "max_downloads": 0,
        "download_count": 0,
        "created_at": datetime.now().isoformat(),
    }
    info.update(fields)
    with share_links_lock:
        SHARE_LINKS[token] = info


def test_password_challenge_renders_html_form(client, app):
    """ISSUE-005: password link GET => 200 text/html with a form."""
    Path(conf.get("folder"), "hello.txt").write_text("hi", encoding="utf-8")
    _put_share("pw-token", password_hash=hash_password("s3cret"))
    try:
        resp = client.get("/share/pw-token")
        assert resp.status_code == 200
        assert "text/html" in resp.content_type
        assert "password" in resp.get_data(as_text=True).lower()
    finally:
        with share_links_lock:
            SHARE_LINKS.pop("pw-token", None)


def test_wrong_password_rerenders_form(client, app):
    """ISSUE-005: wrong password POST => 200 form with an error message."""
    Path(conf.get("folder"), "hello.txt").write_text("hi", encoding="utf-8")
    _put_share("pw-token2", password_hash=hash_password("s3cret"))
    try:
        resp = client.post("/share/pw-token2", data={"password": "nope"})
        assert resp.status_code == 200
        assert "text/html" in resp.content_type
        assert "올바르지 않습니다" in resp.get_data(as_text=True)
    finally:
        with share_links_lock:
            SHARE_LINKS.pop("pw-token2", None)


def test_expired_and_missing_links_render_html(client, app):
    """ISSUE-005: expired (410) and missing (404) links => HTML pages."""
    _put_share("old-token",
               expires=datetime.now() - timedelta(seconds=1))
    try:
        resp = client.get("/share/old-token")
        assert resp.status_code == 410
        assert "text/html" in resp.content_type
    finally:
        with share_links_lock:
            SHARE_LINKS.pop("old-token", None)
    resp = client.get("/share/no-such-token")
    assert resp.status_code == 404
    assert "text/html" in resp.content_type
