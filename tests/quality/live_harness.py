"""Live loopback harness for webshare quality tests.

Spins a REAL Flask server (Werkzeug ``make_server``) on 127.0.0.1 with an
ephemeral port in a background thread, with an isolated root/config dir per
test. All driving is done over real HTTP via :class:`LiveClient` (stdlib
urllib + cookie jar) -- never Flask ``test_client`` or Go ``httptest``.

Safety: loopback only, tmp dirs only, production ports/folders untouched.
"""

from __future__ import annotations

import hashlib
import http.cookiejar
import io
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import pytest

ADMIN_PW = "1234"
GUEST_PW = "0000"

_CSRF_META_RE = re.compile(
    r'<meta\s+name="csrf-token"\s+content="([^"]+)"', re.IGNORECASE
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | os.PathLike) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not follow redirects so tests can assert 302 + Location."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _build_opener(follow_redirects: bool = True):
    jar = http.cookiejar.CookieJar()
    handlers: list[Any] = [urllib.request.HTTPCookieProcessor(jar)]
    if not follow_redirects:
        handlers.append(NoRedirect())
    return urllib.request.build_opener(*handlers), jar


def encode_multipart(
    fields: dict[str, str], files: list[tuple[str, str, bytes, str]]
) -> tuple[bytes, str]:
    """Build a multipart/form-data body with stdlib only."""
    boundary = "----webshare-live-boundary-7d4a"
    buf = io.BytesIO()
    for name, value in fields.items():
        buf.write(f"--{boundary}\r\n".encode())
        buf.write(
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        )
        buf.write(str(value).encode())
        buf.write(b"\r\n")
    for field, filename, data, ctype in files:
        buf.write(f"--{boundary}\r\n".encode())
        buf.write(
            (
                f'Content-Disposition: form-data; name="{field}"; '
                f'filename="{filename}"\r\n'
                f"Content-Type: {ctype}\r\n\r\n"
            ).encode()
        )
        buf.write(data)
        buf.write(b"\r\n")
    buf.write(f"--{boundary}--\r\n".encode())
    return buf.getvalue(), f"multipart/form-data; boundary={boundary}"


class LiveClient:
    """Real HTTP client bound to one live server; keeps its own cookies."""

    def __init__(self, base_url: str, timeout: float = 15.0):
        self.base_url = base_url
        self.timeout = timeout
        self.opener, self.jar = _build_opener(follow_redirects=True)
        self.plain_opener, _ = _build_opener(follow_redirects=False)
        # share the cookie jar with the no-redirect opener
        self.plain_opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect()
        )
        self.csrf_token = ""

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
        content_type: str | None = None,
    ) -> tuple[int, Any, bytes]:
        # Real browsers always offer gzip; the app's Compress middleware
        # serves its buffered (length-known) form then. Without an accepted
        # encoding it falls back to a length-less chunked stream, which the
        # dev WSGI server cannot reliably finish past ~64 KiB.
        url = self.base_url + path
        data: bytes | None = body
        req_headers = {"Accept-Encoding": "gzip"}
        req_headers.update(headers or {})
        if content_type:
            req_headers["Content-Type"] = content_type
        req = urllib.request.Request(
            url, data=data, headers=req_headers, method=method
        )
        opener = self.opener if follow_redirects else self.plain_opener
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding", "") == "gzip":
                    import gzip as _gzip

                    raw = _gzip.decompress(raw)
                return resp.status, resp.headers, raw
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            enc = (exc.headers.get("Content-Encoding", "") or "")
            if enc == "gzip" and raw:
                import gzip as _gzip

                raw = _gzip.decompress(raw)
            return exc.code, exc.headers, raw
        except urllib.error.URLError as exc:  # pragma: no cover - diagnosable
            raise AssertionError(f"live server unreachable: {url}: {exc}")

    def get(self, path: str, **kw) -> tuple[int, Any, bytes]:
        return self._request("GET", path, **kw)

    def get_json(self, path: str, **kw) -> tuple[int, dict]:
        status, _, body = self._request("GET", path, **kw)
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except ValueError:
            payload = {}
        return status, payload if isinstance(payload, dict) else {}

    def post_json(
        self, path: str, obj: dict, *, csrf: bool = True, **kw
    ) -> tuple[int, dict]:
        payload = dict(obj)
        headers: dict[str, str] = {}
        if csrf and self.csrf_token:
            payload.setdefault("csrf_token", self.csrf_token)
            headers["X-CSRF-Token"] = self.csrf_token
        status, _, body = self._request(
            "POST",
            path,
            body=json.dumps(payload).encode(),
            headers=headers,
            content_type="application/json",
            **kw,
        )
        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except ValueError:
            data = {}
        return status, data if isinstance(data, dict) else {}

    def post_multipart(
        self,
        path: str,
        fields: dict[str, str],
        files: list[tuple[str, str, bytes, str]],
        *,
        csrf: bool = True,
        **kw,
    ) -> tuple[int, dict]:
        if csrf and self.csrf_token:
            fields = dict(fields)
            fields.setdefault("csrf_token", self.csrf_token)
            headers = {"X-CSRF-Token": self.csrf_token}
        else:
            headers = {}
        body, ctype = encode_multipart(fields, files)
        status, _, raw = self._request(
            "POST", path, body=body, headers=headers,
            content_type=ctype, **kw,
        )
        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            data = {}
        return status, data if isinstance(data, dict) else {}

    def post_form(
        self, path: str, fields: dict[str, str], **kw
    ) -> tuple[int, Any, bytes]:
        body = urllib.parse.urlencode(fields).encode()
        return self._request(
            "POST", path, body=body,
            content_type="application/x-www-form-urlencoded", **kw,
        )

    # -- session helpers -------------------------------------------------
    def login(self, password: str) -> int:
        """POST / with the password; returns status (expect 302)."""
        status, headers, _ = self.post_form(
            "/", {"password": password}, follow_redirects=False
        )
        assert status == 302, f"login POST returned {status}, want 302"
        location = headers.get("Location", "")
        assert "/browse" in location, f"login redirect -> {location!r}"
        self.refresh_csrf()
        return status

    def refresh_csrf(self) -> str:
        status, _, body = self.get("/browse/")
        assert status == 200, f"GET /browse/ -> {status}, want 200"
        match = _CSRF_META_RE.search(body.decode("utf-8", "replace"))
        assert match, "CSRF meta tag missing in /browse/ HTML"
        self.csrf_token = match.group(1)
        assert len(self.csrf_token) >= 16
        return self.csrf_token


class LiveServer:
    """A running loopback Flask instance with isolated dirs."""

    def __init__(self, base_url: str, root: Path, server, thread, app):
        self.base_url = base_url
        self.root = root
        self.shared = root / "shared"
        self.config_dir = root / "config"
        self._server = server
        self._thread = thread
        self.app = app
        self.clients: list[LiveClient] = []

    def client(self) -> LiveClient:
        c = LiveClient(self.base_url)
        self.clients.append(c)
        return c

    def admin_client(self) -> LiveClient:
        c = self.client()
        c.login(ADMIN_PW)
        return c

    def stop(self) -> None:
        try:
            self._server.shutdown()
        except Exception:
            pass
        self._thread.join(timeout=10)
        assert not self._thread.is_alive(), "live server thread did not stop"

    def restart(self) -> str:
        """Stop and start a fresh app/server on the SAME dirs (new port).

        Simulates a process restart: in-memory state (sessions, chunk
        uploads, locks) is dropped while on-disk state (files, share links,
        config) survives. Returns the new base URL; old client cookies are
        kept by the caller on purpose (restart-auth contract tests).
        """
        import sys as _sys

        self.stop()
        root = Path(__file__).resolve().parents[2]
        if str(root) not in _sys.path:
            _sys.path.insert(0, str(root))
        import webshare_app.server.bootstrap as bootstrap

        bootstrap._runtime_initialized = False
        _reset_global_state()
        bootstrap.ensure_runtime_initialized()

        from webshare_app.app.factory import create_app
        from werkzeug.serving import make_server

        app = create_app()
        app.config.update(TESTING=False)
        self.app = app
        self._server = make_server("127.0.0.1", 0, app, threaded=True)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        self._thread.start()
        self.base_url = f"http://127.0.0.1:{self._server.server_port}"
        for client in self.clients:
            client.base_url = self.base_url
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                with urllib.request.build_opener().open(
                    self.base_url + "/healthz", timeout=2
                ) as resp:
                    if resp.status == 200:
                        return self.base_url
            except Exception:
                time.sleep(0.05)
        raise AssertionError("restarted live server did not answer /healthz")


def _reset_global_state() -> Any:
    """Mirror tests/conftest.py isolation for live (same-process) servers."""
    from config import (
        ACCESS_LOG, ACTIVE_SESSIONS, AUDIT_LOG, BOOKMARKS,
        CLOUD_SYNC_CONFIG, DOWNLOAD_TRACKER, DUPLICATE_SCAN_PROGRESS,
        FAVORITE_FOLDERS, FILE_MEMOS, FILE_TAGS, FOLDER_PERMISSIONS,
        LOGIN_ATTEMPTS, RECENT_FILES, SHARE_LINKS, access_log_lock,
        audit_lock, cloud_sync_lock, conf, download_tracker_lock,
        duplicate_scan_lock, login_attempts_lock, metadata_lock,
        permissions_lock, recent_files_lock, session_lock,
        share_links_lock,
    )
    from features.cloud_sync import reset_cloud_sync_runtime_state
    from features.job_store import reset_jobs_runtime_state
    from features.search_indexer import indexer
    from webshare_app.features.webdav_server import (
        reset_webdav_auth_attempts,
    )
    from webshare_app.services.share_service import (
        reset_share_password_attempts,
    )
    from webshare_app.services.upload_service import (
        reset_upload_runtime_state,
    )

    with login_attempts_lock:
        LOGIN_ATTEMPTS.clear()
    with download_tracker_lock:
        DOWNLOAD_TRACKER.clear()
    with share_links_lock:
        SHARE_LINKS.clear()
    with session_lock:
        ACTIVE_SESSIONS.clear()
    with audit_lock:
        AUDIT_LOG.clear()
    with metadata_lock:
        FILE_TAGS.clear()
        FAVORITE_FOLDERS.clear()
        FILE_MEMOS.clear()
        BOOKMARKS.clear()
    with recent_files_lock:
        RECENT_FILES.clear()
    with access_log_lock:
        ACCESS_LOG.clear()
    with permissions_lock:
        FOLDER_PERMISSIONS.clear()
    with cloud_sync_lock:
        for provider in ("google_drive", "dropbox"):
            CLOUD_SYNC_CONFIG[provider].clear()
            CLOUD_SYNC_CONFIG[provider].update(
                {
                    "enabled": False,
                    "client_id": "",
                    "client_secret": "",
                    "token": None,
                    "folder_id": "",
                    "last_sync": None,
                    "last_job_id": "",
                }
            )
            if provider == "dropbox":
                CLOUD_SYNC_CONFIG[provider].update(
                    {"app_key": "", "app_secret": ""}
                )
    with duplicate_scan_lock:
        DUPLICATE_SCAN_PROGRESS.clear()
        DUPLICATE_SCAN_PROGRESS.update(
            {
                "running": False, "progress": 0, "total": 0,
                "results": [], "last_scan": "", "job_id": "",
                "phase": "", "cancelled": False,
            }
        )
    reset_jobs_runtime_state()
    reset_cloud_sync_runtime_state()
    reset_upload_runtime_state()
    reset_share_password_attempts()
    reset_webdav_auth_attempts()
    indexer.reset_runtime_state()
    return conf


def seed_files(shared_dir, mapping: dict[str, bytes]) -> dict[str, str]:
    """Write seed files under the shared root; return {rel: sha256} oracle."""
    oracle: dict[str, str] = {}
    base = Path(shared_dir)
    for rel, data in mapping.items():
        target = base / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        oracle[rel] = sha256_bytes(data)
    return oracle


def pick_free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class GoClient:
    """Real HTTP client for the Go backend (no redirect following).

    CSRF comes from the signed session cookie payload (base64 JSON part),
    exactly like Go's own ``csrfFor`` test helper -- no secret needed to
    *read* the token, and the server still verifies the signature.
    """

    def __init__(self, base_url: str, timeout: float = 15.0):
        import http.client as _http

        self.base_url = base_url
        self.timeout = timeout
        self._http = _http
        hostport = base_url.split("://", 1)[1]
        host, _, port = hostport.partition(":")
        self._host = host
        self._port = int(port)
        self.cookie = ""
        self.csrf_token = ""

    def _conn(self):
        return self._http.HTTPConnection(
            self._host, self._port, timeout=self.timeout
        )

    def _request(
        self, method: str, path: str,
        body: bytes | None = None, headers: dict | None = None,
    ) -> tuple[int, dict, bytes]:
        conn = self._conn()
        hdrs = {"Accept-Encoding": "gzip"}
        hdrs.update(headers or {})
        if self.cookie:
            hdrs["Cookie"] = self.cookie
        conn.request(method, path, body, hdrs)
        try:
            resp = conn.getresponse()
            raw = resp.read()
            headers_out = dict(resp.getheaders())
            if headers_out.get("Content-Encoding", "") == "gzip" and raw:
                import gzip as _gzip

                raw = _gzip.decompress(raw)
            return resp.status, headers_out, raw
        except Exception as exc:  # pragma: no cover - diagnosable
            raise AssertionError(f"go server unreachable: {path}: {exc}")
        finally:
            conn.close()

    @staticmethod
    def _decode_csrf(cookie_value: str) -> str:
        import base64 as _b64

        raw = cookie_value.split("=", 1)[1].split(";")[0].strip()
        payload_b64 = raw.split(".")[0]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(
            _b64.urlsafe_b64decode(payload_b64).decode("utf-8")
        )
        token = str(payload.get("_csrf_token", ""))
        assert len(token) >= 16, "no csrf token in go session cookie"
        return token

    def login(self, password: str) -> int:
        body = urllib.parse.urlencode({"password": password}).encode()
        status, headers, _ = self._request(
            "POST", "/",
            body,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert status == 302, f"go login POST -> {status}, want 302"
        set_cookie = ""
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                set_cookie = value
                break
        assert set_cookie, "go login set no session cookie"
        self.cookie = set_cookie.split(";")[0]
        self.csrf_token = self._decode_csrf(set_cookie)
        return status

    def get(self, path: str) -> tuple[int, dict, bytes]:
        return self._request("GET", path)

    def get_json(self, path: str) -> tuple[int, dict]:
        import json as _json

        status, _, raw = self._request("GET", path)
        try:
            data = _json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            data = {}
        return status, data if isinstance(data, dict) else {}

    def post_json(self, path: str, obj: dict) -> tuple[int, dict]:
        payload = dict(obj)
        if self.csrf_token:
            payload.setdefault("csrf_token", self.csrf_token)
        body = json.dumps(payload).encode()
        status, _, raw = self._request(
            "POST", path, body,
            {
                "Content-Type": "application/json",
                "X-CSRF-Token": self.csrf_token,
            },
        )
        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            data = {}
        return status, data if isinstance(data, dict) else {}

    def post_multipart(
        self, path: str, fields: dict[str, str],
        files: list[tuple[str, str, bytes, str]],
    ) -> tuple[int, dict]:
        if self.csrf_token:
            fields = dict(fields)
            fields.setdefault("csrf_token", self.csrf_token)
        body, ctype = encode_multipart(fields, files)
        status, _, raw = self._request(
            "POST", path, body,
            {"Content-Type": ctype, "X-CSRF-Token": self.csrf_token},
        )
        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            data = {}
        return status, data if isinstance(data, dict) else {}

    def post_form(self, path: str, fields: dict[str, str]):
        body = urllib.parse.urlencode(fields).encode()
        return self._request(
            "POST", path, body,
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "X-CSRF-Token": self.csrf_token,
            },
        )


class GoLiveServer:
    """A running Go backend subprocess with isolated root/config."""

    def __init__(self, base_url, work: Path, proc, binary_sha: str,
                 config_path=None):
        self.base_url = base_url
        self.work = work
        self.shared = work / "shared"
        self._proc = proc
        self.binary_sha = binary_sha
        self.pid = proc.pid
        self._config_path = Path(config_path) if config_path else None

    def client(self) -> GoClient:
        return GoClient(self.base_url)

    def admin_client(self) -> GoClient:
        c = self.client()
        c.login(ADMIN_PW)
        return c

    def stop(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
            proc.wait(timeout=10)
        assert proc.poll() is not None, "go server process survived stop"

    def restart(self) -> str:
        """Stop and start a fresh Go process on the SAME dirs (new port).

        On-disk state (files, persisted share links, config) survives;
        in-memory state does not. Returns the new base URL.
        """
        import secrets as _secrets
        import subprocess as _subprocess

        self.stop()
        assert self._config_path, "go restart needs the config path"
        from webshare_app.server import go_process as _go_process

        binary = _go_process.find_binary()
        assert binary and Path(binary).is_file(), "go binary vanished"
        port = pick_free_port()
        env = dict(os.environ)
        env["WEBSHARE_CONTROL_TOKEN"] = _secrets.token_hex(32)
        proc = _subprocess.Popen(
            [binary, "serve", "-host", "127.0.0.1",
             "-port", str(port), "-config", str(self._config_path)],
            env=env,
            stdout=_subprocess.DEVNULL,
            stderr=_subprocess.DEVNULL,
        )
        base_url = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 20
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            try:
                with urllib.request.build_opener().open(
                    base_url + "/", timeout=2
                ) as resp:
                    ready = resp.status in (200, 302)
            except urllib.error.HTTPError as exc:
                ready = exc.code == 401
                if ready:
                    break
            except Exception:
                time.sleep(0.1)
        assert ready and proc.poll() is None, "restarted go server not ready"
        self._proc = proc
        self.base_url = base_url
        self.pid = proc.pid
        return base_url


@pytest.fixture
def live_server(tmp_path, monkeypatch):
    """Start a real HTTP server on 127.0.0.1:<ephemeral> (function scope)."""
    import sys

    root = Path(__file__).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    work = tmp_path / "live"
    shared = work / "shared"
    cfgdir = work / "config"
    shared.mkdir(parents=True)
    cfgdir.mkdir(parents=True)

    old_config_dir = os.environ.get("WEBSHARE_CONFIG_DIR")
    old_config_file = None
    import webshare_app.core.config.manager as config_manager

    old_config_file = config_manager.CONFIG_FILE
    monkeypatch.setenv("WEBSHARE_CONFIG_DIR", str(cfgdir))
    monkeypatch.setattr(
        config_manager, "CONFIG_FILE", str(cfgdir / "webshare_config.json")
    )

    import webshare_app.server.bootstrap as bootstrap

    conf = _reset_global_state()
    old_conf = dict(conf.config)
    # Reset EVERY key the existing suite ever mutates (see tests/*.py):
    # a leftover use_https=True would set Secure cookies that plain-HTTP
    # loopback clients silently drop, failing all later logins.
    conf.set("folder", str(shared))
    conf.set("allow_guest_upload", False)
    conf.set("ip_whitelist", [])
    conf.set("daily_download_limit", 0)
    conf.set("daily_bandwidth_limit_mb", 0)
    conf.set("trusted_proxies", [])
    conf.set("trusted_hops", 1)
    conf.set("webdav_allow_insecure", False)
    conf.set("session_timeout", 60)
    conf.set("display_host", "127.0.0.1")
    conf.set("use_https", False)
    conf.config["admin_pw"] = ADMIN_PW
    conf.config["guest_pw"] = GUEST_PW

    bootstrap._runtime_initialized = False
    bootstrap.ensure_runtime_initialized()

    from webshare_app.app.factory import create_app
    from werkzeug.serving import make_server

    app = create_app()
    app.config.update(TESTING=False)
    server = make_server("127.0.0.1", 0, app, threaded=True)
    port = server.server_port
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05},
        daemon=True,
    )
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    # readiness: real HTTP poll, PID + port proof
    deadline = time.monotonic() + 15
    ready = False
    _probe_opener = urllib.request.build_opener()
    while time.monotonic() < deadline:
        try:
            with _probe_opener.open(
                base_url + "/healthz", timeout=2
            ) as resp:
                if resp.status == 200:
                    ready = True
                    break
        except Exception:
            time.sleep(0.05)
    assert ready, "live server did not answer /healthz on 127.0.0.1"

    live = LiveServer(base_url, work, server, thread, app)
    yield live

    live.stop()
    bootstrap._runtime_initialized = False
    _reset_global_state()
    conf.config.clear()
    conf.config.update(old_conf)
    if old_config_dir is None:
        monkeypatch.delenv("WEBSHARE_CONFIG_DIR", raising=False)
    # CONFIG_FILE restored automatically by monkeypatch.
    assert not thread.is_alive(), "server thread leaked after teardown"


def _find_go_binary() -> str | None:
    from webshare_app.server import go_process

    found = go_process.find_binary()
    if found and Path(found).is_file():
        return str(found)
    return None


@pytest.fixture
def go_live_server(tmp_path):
    """Start the REAL Go backend subprocess (isolated root/config/port).

    Skips (BLOCKED) when the Go binary is unavailable. Records the binary
    SHA-256 and PID so the verification report can cite them.
    """
    import secrets as _secrets
    import subprocess as _subprocess

    binary = _find_go_binary()
    if binary is None:
        pytest.skip("Go binary unavailable (BLOCKED: go backend not built)")

    work = tmp_path / "go-live"
    shared = work / "shared"
    shared.mkdir(parents=True)
    binary_sha = sha256_file(binary)
    port = pick_free_port()
    config = {
        "folder": str(shared),
        "port": port,
        "admin_pw": ADMIN_PW,
        "guest_pw": GUEST_PW,
        "allow_guest_upload": False,
        "display_host": "127.0.0.1",
        "use_https": False,
        "session_timeout": 60,
        "language": "ko",
        "ip_whitelist": [],
        "daily_download_limit": 0,
        "daily_bandwidth_limit_mb": 0,
        "trusted_proxies": [],
        "trusted_hops": 1,
        "webdav_allow_insecure": False,
        "secret_key": _secrets.token_hex(32),
    }
    cfg_path = work / "webshare_config.json"
    cfg_path.write_text(json.dumps(config), encoding="utf-8")

    env = dict(os.environ)
    env["WEBSHARE_CONTROL_TOKEN"] = _secrets.token_hex(32)
    proc = _subprocess.Popen(
        [binary, "serve", "-host", "127.0.0.1",
         "-port", str(port), "-config", str(cfg_path)],
        env=env,
        stdout=_subprocess.DEVNULL,
        stderr=_subprocess.DEVNULL,
    )
    base_url = f"http://127.0.0.1:{port}"
    # readiness: GET / must answer 401 JSON while logged out (Go contract).
    deadline = time.monotonic() + 20
    ready = False
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        try:
            with urllib.request.build_opener().open(
                base_url + "/", timeout=2
            ) as resp:
                ready = resp.status in (200, 302)
        except urllib.error.HTTPError as exc:
            ready = exc.code == 401
            if ready:
                break
        except Exception:
            time.sleep(0.1)
    assert ready and proc.poll() is None, "go server did not become ready"

    live = GoLiveServer(base_url, work, proc, binary_sha,
                        config_path=cfg_path)
    yield live

    live.stop()
    assert proc.poll() is not None, "go server process leaked after stop"
