"""Milestone C live contract: Python reference vs Go port over real HTTP.

Twin servers share one fixture tree and equivalent configs. Every case
fetches both sides and compares status, parsed JSON (volatile keys
normalized), headers, and bytes. The harness never touches user files:
everything lives under tmp_path.
"""

import http.client
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from http.cookiejar import CookieJar
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
GO_EXE = REPO / "go-core" / "webshare-core.exe"
FIXED_MTIME = 1700000000
ADMIN_PW = "admin-contract-pw"
GUEST_PW = "guest-contract-pw"
SECRET = "contract-secret-key-0123456789abcdef0123456789abcdef01234567"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_tree(root: Path):
    files = {
        "hello.txt": "Hello WebShare!\n" * 100,
        "notes.txt": "plain notes",
        "한글노트.txt": "korean name content",
        "photo.jpg": "FAKEJPEG" * 200,
        "movie.mp4": "FAKEMP4" * 500,
        "doc.md": "# Title\n\nbody\n",
        "data.bin": bytes(range(256)) * 4,
        "sub/nested.txt": "nested content here",
        "sub/deep/x.log": "log line\n" * 50,
        "private/secret.txt": "admins only",
        ".hidden": "nope",
        ".webshare/internal.txt": "protected",
    }
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(p, mode, encoding=None if isinstance(content, bytes) else "utf-8") as f:
            f.write(content)
    (root / "emptydir").mkdir(parents=True, exist_ok=True)
    # A real zip with a dir entry inside.
    zpath = root / "archive.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", "aaa")
        zf.writestr("folder/b.txt", "b" * 1000)
    for p in root.rglob("*"):
        if p.is_file() or p.is_dir():
            os.utime(p, (FIXED_MTIME, FIXED_MTIME))


def passwords():
    from security.auth import hash_password

    return hash_password(ADMIN_PW), hash_password(GUEST_PW)


@pytest.fixture(scope="module")
def twin():
    if not GO_EXE.is_file():
        pytest.skip("webshare-core.exe not built")
    import tempfile

    work = Path(tempfile.mkdtemp(prefix="contract-c-"))
    shared = work / "shared"
    shared.mkdir()
    build_tree(shared)
    admin_hash, guest_hash = passwords()

    # ---- Python live server ----
    import config as config_mod
    from webshare_app.server import build_composed_wsgi_app, make_server
    from webshare_app.server.bootstrap import ensure_runtime_initialized

    ensure_runtime_initialized()

    saved_conf = dict(config_mod.conf.config)
    saved_perms = dict(config_mod.FOLDER_PERMISSIONS)
    config_mod.FOLDER_PERMISSIONS.clear()
    config_mod.FOLDER_PERMISSIONS.update(
        {"private": {"read": ["admin"], "write": ["admin"], "delete": ["admin"]}})
    config_mod.conf.config.update({
        "folder": str(shared), "admin_pw": admin_hash, "guest_pw": guest_hash,
        "secret_key": SECRET, "session_timeout": 60, "port": 0,
        "allow_guest_upload": False, "display_host": "127.0.0.1",
        "use_https": False, "ip_whitelist": [], "daily_download_limit": 0,
        "daily_bandwidth_limit_mb": 0, "trusted_proxies": [], "trusted_hops": 1,
        "language": "ko",
    })
    py_port = free_port()
    flask_app, wsgi_app = build_composed_wsgi_app()
    py_server = make_server("127.0.0.1", py_port, wsgi_app, threaded=True)
    py_thread = threading.Thread(target=py_server.serve_forever, daemon=True)
    py_thread.start()

    # ---- Go live server ----
    go_port = free_port()
    go_cfg = {
        "folder": str(shared), "port": go_port, "admin_pw": admin_hash,
        "guest_pw": guest_hash, "allow_guest_upload": False,
        "display_host": "127.0.0.1", "use_https": False, "session_timeout": 60,
        "enable_notifications": True, "enable_versioning": True,
        "minimize_to_tray": True, "language": "ko", "ip_whitelist": [],
        "daily_download_limit": 0, "daily_bandwidth_limit_mb": 0,
        "disk_warning_threshold": 90, "trash_auto_delete_days": 30,
        "close_to_tray": True, "autostart": False, "trusted_proxies": [],
        "trusted_hops": 1, "webdav_allow_insecure": False, "secret_key": SECRET,
    }
    go_cfg_path = work / "go_config.json"
    go_cfg_path.write_text(json.dumps(go_cfg), encoding="utf-8")
    (shared / ".webshare_permissions.json").write_text(
        json.dumps({"private": {"read": ["admin"], "write": ["admin"],
                                "delete": ["admin"]}}), encoding="utf-8")
    env = dict(os.environ, WEBSHARE_CONTROL_TOKEN="contract-token")
    go_log = open(work / "go-server.log", "w", encoding="utf-8")
    go_proc = subprocess.Popen(
        [str(GO_EXE), "serve", "--config", str(go_cfg_path),
         "--host", "127.0.0.1", "--port", str(go_port)],
        env=env, stdout=go_log, stderr=subprocess.STDOUT)
    print(f"contract work dir (kept on failure): {work}")

    def wait(url):
        for _ in range(100):
            try:
                with urllib.request.urlopen(url, timeout=2) as r:
                    if r.status == 200:
                        return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError(f"server not ready: {url}")

    try:
        wait(f"http://127.0.0.1:{py_port}/readyz")
        wait(f"http://127.0.0.1:{go_port}/readyz")
    except Exception:
        go_proc.terminate()
        py_server.shutdown()
        raise
    yield {"py": f"http://127.0.0.1:{py_port}", "go": f"http://127.0.0.1:{go_port}"}
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{go_port}/_control/shutdown", data=b"",
            method="POST", headers={"X-Control-Token": "contract-token"})
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass
    go_proc.wait(timeout=15)
    py_server.shutdown()
    py_server.server_close()
    # Runtime dict surgery on the ConfigData TypedDict: restore the exact
    # pre-test config (clear + update), which type checkers cannot model.
    config_mod.conf.config.clear()  # pyright: ignore[reportAttributeAccessIssue]
    config_mod.conf.config.update(saved_conf)  # pyright: ignore[reportCallIssue, reportArgumentType]
    config_mod.FOLDER_PERMISSIONS.clear()
    config_mod.FOLDER_PERMISSIONS.update(saved_perms)
    go_log.close()
    # Work dir (with go-server.log) is intentionally kept for post-mortem;
    # the OS temp cleaner reclaims it.


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class TwinClient:
    """Cookie-keeping client used against both backends (no auto-redirect).

    Every request sends Connection: close, and every request retries transport
    errors: even a minimal Go net/http hello server RSTs ~15% of loopback
    requests on this machine (proven with a hello-world binary), while the
    Werkzeug server never does and the Go server always logs a complete
    response. Retries therefore only overcome an environmental transport
    flake; any real server defect still fails every attempt loudly.
    """

    def __init__(self, base):
        self.base = base
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())

    TRANSIENT = (ConnectionResetError, TimeoutError, ConnectionAbortedError,
                 BrokenPipeError, http.client.IncompleteRead,
                 http.client.BadStatusLine, http.client.RemoteDisconnected,
                 OSError)

    def _open(self, req, timeout):
        last = None
        for attempt in range(6):
            try:
                with self.opener.open(req, timeout=timeout) as r:
                    return r.status, dict(r.headers), r.read()
            except urllib.error.HTTPError as e:
                return e.code, dict(e.headers or {}), e.read()
            except self.TRANSIENT as e:
                last = e
                time.sleep(0.2 * (attempt + 1))
        assert last is not None  # loop always runs; non-transient paths return
        raise last

    def login(self, password):
        data = urllib.parse.urlencode({"password": password}).encode()
        req = urllib.request.Request(self.base + "/", data=data, method="POST",
                                     headers={"Connection": "close"})
        status, headers, _ = self._open(req, 15)
        loc = ""
        for k, v in headers.items():
            if k.lower() == "location":
                loc = v
        return status, loc

    def get(self, path, headers=None, data=None, method="GET"):
        merged = {"Connection": "close"}
        merged.update(headers or {})
        req = urllib.request.Request(self.base + path, data=data,
                                     method=method, headers=merged)
        return self._open(req, 15)


def test_login_admin_guest(twin):
    for base in (twin["py"], twin["go"]):
        c = TwinClient(base)
        status, loc = c.login(ADMIN_PW)
        assert status == 302 and loc == "/browse/", base
        c = TwinClient(base)
        status, loc = c.login(GUEST_PW)
        assert status == 302 and loc == "/browse/", base
        c = TwinClient(base)
        status, _ = c.login("wrong")
        assert status in (200, 401), (base, status)


def compare_json(py_doc, go_doc, drop=(), float_tol=0.01):
    if isinstance(py_doc, dict) and isinstance(go_doc, dict):
        assert set(py_doc) == set(go_doc), (set(py_doc) ^ set(go_doc))
        for k in py_doc:
            if k in drop:
                continue
            compare_json(py_doc[k], go_doc[k], drop, float_tol)
    elif isinstance(py_doc, list) and isinstance(go_doc, list):
        assert len(py_doc) == len(go_doc), (len(py_doc), len(go_doc))
        for a, b in zip(py_doc, go_doc):
            compare_json(a, b, drop, float_tol)
    elif isinstance(py_doc, float) and isinstance(go_doc, float):
        assert abs(py_doc - go_doc) <= float_tol, (py_doc, go_doc)
    else:
        assert py_doc == go_doc, (py_doc, go_doc)


def authed_pair(twin, role_pw):
    clients = {}
    for name, base in twin.items():
        c = TwinClient(base)
        status, _ = c.login(role_pw)
        assert status == 302, (name, status)
        clients[name] = c
    return clients


def test_list_root(twin):
    clients = authed_pair(twin, ADMIN_PW)
    docs = {}
    for name, c in clients.items():
        status, headers, body = c.get("/api/list/")
        assert status == 200, (name, status, body[:200])
        docs[name] = json.loads(body)
    py, go = docs["py"], docs["go"]
    compare_json(py, go, drop=("mtime", "request_id"))
    assert [i["name"] for i in py["items"]] == [i["name"] for i in go["items"]]
    # dotfiles hidden, protected present-but-filtered for read? .webshare
    # items must not leak.
    names = [i["name"] for i in go["items"]]
    assert ".hidden" not in names
    assert not any(n.startswith(".webshare") for n in names)


def test_list_variants(twin):
    clients = authed_pair(twin, ADMIN_PW)
    for path in ("/api/list/sub", "/api/list/?page=1&page_size=20",
                 "/api/list/?sort=size&order=desc", "/api/list/?q=txt",
                 "/api/list/?sort=date&order=desc"):
        docs = {}
        for name, c in clients.items():
            status, _, body = c.get(path)
            assert status == 200, (name, path, status)
            docs[name] = json.loads(body)
        compare_json(docs["py"], docs["go"], drop=("mtime", "request_id"))
        assert [i["name"] for i in docs["py"]["items"]] == \
               [i["name"] for i in docs["go"]["items"]], path


def test_guest_permission_filter(twin):
    clients = authed_pair(twin, GUEST_PW)
    for name, c in clients.items():
        status, _, body = c.get("/api/list/")
        assert status == 200, name
        names = [i["name"] for i in json.loads(body)["items"]]
        assert "private" not in names, name
        status, _, _ = c.get("/file_info/private/secret.txt")
        assert status == 403, (name, status)


def test_file_info(twin):
    clients = authed_pair(twin, ADMIN_PW)
    docs = {}
    for name, c in clients.items():
        status, _, body = c.get("/file_info/hello.txt")
        assert status == 200, (name, status)
        docs[name] = json.loads(body)
    compare_json(docs["py"], docs["go"],
                 drop=("created", "accessed", "mtime", "request_id"))
    assert docs["go"]["md5"] == docs["py"]["md5"]
    assert docs["go"]["mime_type"] == docs["py"]["mime_type"] == "text/plain"
    assert docs["go"]["size"] == docs["py"]["size"]
    for name, c in clients.items():
        status, _, body = c.get("/file_info/sub")
        assert status == 200, name
        doc = json.loads(body)
        assert doc["is_dir"] is True and "file_count" in doc, name
    for name, c in clients.items():
        for path, want in (("/file_info/nope.txt", 404),
                           ("/file_info/.webshare/internal.txt", 403)):
            status, _, _ = c.get(path)
            assert status == want, (name, path, status)


def test_download_bytes_and_headers(twin):
    clients = authed_pair(twin, ADMIN_PW)
    got = {}
    for name, c in clients.items():
        status, headers, body = c.get("/download/hello.txt")
        assert status == 200, (name, status)
        got[name] = (headers, body)
    assert got["py"][1] == got["go"][1]
    for key in ("Content-Type", "Content-Disposition", "Content-Length",
                "Accept-Ranges"):
        assert got["py"][0].get(key) == got["go"][0].get(key), key
    for name, c in clients.items():
        for path, want in (("/download/sub", 400), ("/download/nope.txt", 404),
                           ("/download/.webshare/internal.txt", 403)):
            status, _, _ = c.get(path)
            assert status == want, (name, path, status)


def test_download_ranges(twin):
    clients = authed_pair(twin, ADMIN_PW)
    full = {}
    for name, c in clients.items():
        _, _, body = c.get("/download/data.bin")
        full[name] = body
    assert full["py"] == full["go"]
    n = len(full["py"])
    for rng, start, end in (("bytes=0-99", 0, 99),
                            (f"bytes={n-100}-", n - 100, n - 1),
                            ("bytes=-50", n - 50, n - 1)):
        parts = {}
        for name, c in clients.items():
            status, headers, body = c.get("/download/data.bin",
                                          headers={"Range": rng})
            assert status == 206, (name, rng, status)
            parts[name] = (headers, body)
        assert parts["py"][1] == parts["go"][1] == full["py"][start:end + 1]
        assert parts["py"][0].get("Content-Range") == \
            parts["go"][0].get("Content-Range") == f"bytes {start}-{end}/{n}"


def zip_map(body):
    out = {}
    with zipfile.ZipFile(io.BytesIO(body)) as zf:
        for info in zf.infolist():
            out[info.filename] = (info.file_size, info.CRC)
    return out


def test_zip_folder(twin):
    clients = authed_pair(twin, ADMIN_PW)
    got = {}
    for name, c in clients.items():
        status, headers, body = c.get("/zip/sub")
        assert status == 200, (name, status, body[:200])
        got[name] = (headers, body)
    assert zip_map(got["py"][1]) == zip_map(got["go"][1])
    assert got["py"][0].get("Content-Type") == got["go"][0].get("Content-Type")
    assert got["py"][0].get("Content-Disposition") == \
        got["go"][0].get("Content-Disposition")
    for name, c in clients.items():
        status, _, _ = c.get("/zip/hello.txt")
        assert status == 404, (name, status)


def csrf_from_jar(client, base, py_base):
    """Read _csrf_token out of the signed session cookie (same SECRET both
    sides). Python mints the token lazily at page render, so fetch one page
    first on the Python side; Go mints it eagerly at login.
    Browser-observable outcome is the same: a token exists before any
    state-changing POST."""
    import hashlib
    from itsdangerous import URLSafeTimedSerializer
    from flask.json.tag import TaggedJSONSerializer

    if base == py_base:
        client.get("/browse/")
    for cookie in client.jar:
        if cookie.name == "session":
            s = URLSafeTimedSerializer(
                SECRET, salt="cookie-session", serializer=TaggedJSONSerializer(),
                signer_kwargs={"key_derivation": "hmac",
                               "digest_method": hashlib.sha1})
            payload = s.loads(cookie.value, max_age=31 * 24 * 3600)
            assert "_csrf_token" in payload, base
            return payload["_csrf_token"]
    raise AssertionError(f"no session cookie: {base}")


def test_batch_download(twin):
    # The UI posts to /batch_download/<currentdir> (never empty — Flask 404s
    # empty subpaths, and Go matches that).
    clients = authed_pair(twin, ADMIN_PW)
    got = {}
    for name, c in clients.items():
        token = csrf_from_jar(c, twin[name], twin["py"])
        form = urllib.parse.urlencode(
            {"files": json.dumps(["nested.txt", "deep"])}).encode()
        status, _, body = c.get("/batch_download/sub", data=form, method="POST",
                                headers={"Content-Type":
                                         "application/x-www-form-urlencoded",
                                         "X-CSRF-Token": token})
        assert status == 200, (name, status, body[:200])
        got[name] = body
    assert zip_map(got["py"]) == zip_map(got["go"])
    assert "deep/x.log" in zip_map(got["go"])
    for name, c in clients.items():
        form = urllib.parse.urlencode({"files": "nope"}).encode()
        status, _, _ = c.get("/batch_download/sub", data=form, method="POST",
                             headers={"Content-Type":
                                      "application/x-www-form-urlencoded",
                                      "X-CSRF-Token": csrf_from_jar(c, twin[name],
                                                                   twin["py"])})
        assert status == 400, (name, status)


def test_zip_preview(twin):
    clients = authed_pair(twin, ADMIN_PW)
    docs = {}
    for name, c in clients.items():
        status, _, body = c.get("/api/zip_preview/archive.zip")
        assert status == 200, (name, status)
        docs[name] = json.loads(body)
    compare_json(docs["py"], docs["go"], drop=("request_id",))
    for name, c in clients.items():
        status, _, _ = c.get("/api/zip_preview/hello.txt")
        assert status == 400, (name, status)


def test_search(twin):
    clients = authed_pair(twin, ADMIN_PW)
    docs = {}
    for name, c in clients.items():
        status, _, body = c.get("/search?q=" + urllib.parse.quote("note"))
        assert status == 200, (name, status)
        docs[name] = json.loads(body)
    py_paths = sorted(i["path"] for i in docs["py"]["results"])
    go_paths = sorted(i["path"] for i in docs["go"]["results"])
    assert py_paths == go_paths and len(py_paths) > 0
    for name, c in clients.items():
        status, _, body = c.get("/search?q=x")
        assert status == 200, name
        assert json.loads(body)["results"] == [], name


def test_unauthenticated(twin):
    for base in (twin["py"], twin["go"]):
        c = TwinClient(base)
        status, _, _ = c.get("/api/list/")
        assert status == 401, (base, status)
        status, headers, _ = c.get("/download/hello.txt")
        assert status == 302 and headers.get("Location") == "/", (base, status)


def test_quota_smoke(twin):
    # High-limit smoke: downloads succeed on both sides without false
    # positives (threshold logic is covered by unit suites on both sides;
    # Go's 429 HTTP mapping by handlers_test).
    clients = authed_pair(twin, ADMIN_PW)
    for name, c in clients.items():
        status, _, body = c.get("/download/hello.txt")
        assert status == 200 and len(body) > 0, (name, status)


def test_traversal_blocked(twin):
    # A ".." segment trips the protected-path rule (startswith(".")) on both
    # sides, so traversal is 403 — never a 400/404 escape.
    clients = authed_pair(twin, ADMIN_PW)
    for name, c in clients.items():
        status, _, _ = c.get("/file_info/%2e%2e/x")
        assert status == 403, (name, status)
        status, _, _ = c.get("/download/%2e%2e/webshare_config.json")
        assert status == 403, (name, status)
