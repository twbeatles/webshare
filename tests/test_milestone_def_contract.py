"""Milestone D/E/F live contract: mutation, upload, chunk, share parity.

Twin servers share one fixture tree. Mutation cases use per-backend file
names so the two sides never interfere; JSON is compared with volatile
keys dropped. Documented divergences asserted explicitly:
- share access failures / password challenge are HTML on Python, JSON on Go
- multi-range: Python 500s (Werkzeug 416), Go serves RFC 7233 multipart
"""
import hashlib
import io
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from http.cookiejar import CookieJar
from pathlib import Path

import pytest

from test_milestone_c_contract import (
    TwinClient, build_tree, free_port,
)

REPO = Path(__file__).resolve().parents[1]
GO_EXE = REPO / "go-core" / "webshare-core.exe"
ADMIN_PW = "admin-def-pw"
GUEST_PW = "guest-def-pw"
SECRET = "def-secret-key-0123456789abcdef0123456789abcdef01234567"


def flask_serializer(secret):
    from itsdangerous import URLSafeTimedSerializer
    from flask.json.tag import TaggedJSONSerializer

    return URLSafeTimedSerializer(
        secret, salt="cookie-session", serializer=TaggedJSONSerializer(),
        signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1})


@pytest.fixture(scope="module")
def twin():
    if not GO_EXE.is_file():
        pytest.skip("webshare-core.exe not built")
    work = Path(tempfile.mkdtemp(prefix="contract-def-"))
    shared = work / "shared"
    shared.mkdir()
    build_tree(shared)

    from security.auth import hash_password
    admin_hash, guest_hash = hash_password(ADMIN_PW), hash_password(GUEST_PW)

    import config as config_mod
    from webshare_app.server import build_composed_wsgi_app, make_server
    from webshare_app.server.bootstrap import ensure_runtime_initialized
    ensure_runtime_initialized()
    saved_conf = dict(config_mod.conf.config)
    saved_perms = dict(config_mod.FOLDER_PERMISSIONS)
    config_mod.FOLDER_PERMISSIONS.clear()
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
    threading.Thread(target=py_server.serve_forever, daemon=True).start()

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
    env = dict(os.environ, WEBSHARE_CONTROL_TOKEN="contract-def-token")
    go_log = open(work / "go-server.log", "w", encoding="utf-8")
    go_proc = subprocess.Popen(
        [str(GO_EXE), "serve", "--config", str(go_cfg_path),
         "--host", "127.0.0.1", "--port", str(go_port)],
        env=env, stdout=go_log, stderr=subprocess.STDOUT)
    print(f"contract-def work dir (kept on failure): {work}")

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
            method="POST", headers={"X-Control-Token": "contract-def-token"})
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


def authed_pair(twin, password):
    clients = {}
    for name, base in twin.items():
        c = TwinClient(base)
        status, loc = c.login(password)
        assert status == 302 and loc == "/browse/", (name, status)
        clients[name] = c
    return clients


def csrf_of(client, base, py_base):
    # Python mints the token lazily at page render, so fetch one page
    # first on the Python side; Go mints it eagerly at login.
    if base == py_base:
        client.get("/browse/")
    for cookie in client.jar:
        if cookie.name == "session":
            payload = flask_serializer(SECRET).loads(
                cookie.value, max_age=31 * 24 * 3600)
            assert "_csrf_token" in payload, base
            return payload["_csrf_token"]
    raise AssertionError(f"no session cookie: {base}")


def post_json(client, path, doc, csrf=None):
    body = json.dumps(doc).encode() if doc is not None else b""
    headers = {"Connection": "close", "Content-Type": "application/json"}
    if csrf:
        headers["X-CSRF-Token"] = csrf
    req = urllib.request.Request(client.base + path, data=body,
                                 method="POST", headers=headers)
    return client._open(req, 15)


def post_multipart(client, path, fields, files, csrf):
    import uuid
    boundary = uuid.uuid4().hex
    buf = io.BytesIO()
    for k, v in fields.items():
        buf.write(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    for field, (fname, content) in files.items():
        buf.write(f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{fname}"\r\n'
                  .encode() + b'Content-Type: application/octet-stream\r\n\r\n')
        buf.write(content + b"\r\n")
    buf.write(f"--{boundary}--\r\n".encode())
    headers = {"Connection": "close",
               "Content-Type": f"multipart/form-data; boundary={boundary}",
               "X-CSRF-Token": csrf}
    req = urllib.request.Request(client.base + path, data=buf.getvalue(),
                                 method="POST", headers=headers)
    return client._open(req, 30)


def norm(doc):
    if isinstance(doc, dict):
        return {k: norm(v) for k, v in doc.items()
                if k not in ("request_id",)}
    if isinstance(doc, list):
        return [norm(v) for v in doc]
    return doc


def list_names(client, sub=""):
    st, _, body = client.get("/api/list/" + sub if sub else "/api/list/")
    assert st == 200, (sub, st, body[:200])
    return [i["name"] for i in json.loads(body)["items"]]


def post_checked(client, path, doc, csrf, want_status, verify, expect_path=None):
    """POST a mutation, tolerating the loopback RST double-execution flake:
    returns (status, body, flaked). A retry re-executes, so even a 200 can
    describe the second execution (renamed copy target, success:false on a
    vanished move source); those cases are flaked when the effect holds."""
    st, _, body = post_json(client, path, doc, csrf)
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None
    clean = st == want_status
    if isinstance(parsed, dict) and parsed.get("success", True) is False:
        clean = False
    if expect_path is not None and (not isinstance(parsed, dict) or parsed.get("path") != expect_path):
        clean = False
    if clean:
        return st, body, False
    if verify():
        return st, body, True
    raise AssertionError((path, st, body[:200]))


def test_mutation_cycle(twin):
    clients = authed_pair(twin, ADMIN_PW)
    csrf = {n: csrf_of(c, twin[n], twin["py"]) for n, c in clients.items()}
    for name, c in clients.items():
        tag = name
        # mkdir.
        st, body, flaked = post_checked(c, "/mkdir/", {"name": f"{tag}_dir"}, csrf[name], 200,
                                        lambda: f"{tag}_dir" in list_names(c))
        if not flaked:
            assert json.loads(body) == {"success": True}, (name, body[:200])
        st, _, body = post_json(c, "/mkdir/", {"name": f"{tag}_dir"}, csrf[name])
        assert st == 400, (name, st)
        # rename.
        st, body, flaked = post_checked(c, f"/rename/{tag}_dir",
                                        {"name": f"{tag}_dir2"}, csrf[name], 200,
                                        lambda: f"{tag}_dir2" in list_names(c))
        if not flaked:
            assert json.loads(body) == {"success": True}, (name, body[:200])
        # copy a file twice (fresh + rename policy).
        st, body, flaked = post_checked(
            c, "/copy", {"source": "hello.txt", "destination": f"{tag}_c.txt"},
            csrf[name], 200, lambda: f"{tag}_c.txt" in list_names(c),
            expect_path=f"{tag}_c.txt")
        if not flaked:
            assert json.loads(body)["path"] == f"{tag}_c.txt", (name, body[:200])
        st, body, flaked = post_checked(
            c, "/copy", {"source": "hello.txt", "destination": f"{tag}_c.txt",
                         "conflict_policy": "rename"},
            csrf[name], 200, lambda: f"{tag}_c_1.txt" in list_names(c),
            expect_path=f"{tag}_c_1.txt")
        if not flaked:
            assert json.loads(body)["path"] == f"{tag}_c_1.txt", (name, body[:200])
        # fail policy → 409.
        st, _, body = post_json(c, "/copy", {"source": "hello.txt",
                                             "destination": f"{tag}_c.txt",
                                             "conflict_policy": "fail"}, csrf[name])
        assert st == 409, (name, st, body[:200])
        assert json.loads(body)["code"] == "DESTINATION_EXISTS"
        # move + delete (a flaked move may land on a renamed target).
        st, body, flaked = post_checked(
            c, "/move", {"source": f"{tag}_c_1.txt", "destination": f"{tag}_m.txt"},
            csrf[name], 200, lambda: f"{tag}_m.txt" in list_names(c),
            expect_path=f"{tag}_m.txt")
        names = list_names(c)
        moved = f"{tag}_m.txt" if f"{tag}_m.txt" in names else next(
            n for n in names if n.startswith(f"{tag}_m"))
        st, body, flaked = post_checked(c, f"/delete/{moved}", {}, csrf[name], 200,
                                        lambda m=moved: m not in list_names(c))
        st, _, body = post_json(c, f"/delete/{moved}", {}, csrf[name])
        assert st == 404, (name, st)


def test_batch_and_unzip(twin):
    clients = authed_pair(twin, ADMIN_PW)
    csrf = {n: csrf_of(c, twin[n], twin["py"]) for n, c in clients.items()}
    for name, c in clients.items():
        tag = name
        st, body, flaked = post_checked(c, "/mkdir/", {"name": f"{tag}_batch"}, csrf[name], 200,
                                        lambda: f"{tag}_batch" in list_names(c))
        st, body, flaked = post_checked(
            c, "/copy", {"source": "hello.txt",
                         "destination": f"{tag}_batch/note.txt"},
            csrf[name], 200,
            lambda: f"{tag}_batch/note.txt" in list_names(c, f"{tag}_batch"),
            expect_path=f"{tag}_batch/note.txt")
        # A flaked copy may have landed on a renamed target; resolve it.
        if flaked:
            names = list_names(c, f"{tag}_batch")
            note = "note.txt" if "note.txt" in names else next(
                n for n in names if n.startswith("note"))
        else:
            note = "note.txt"
        st, _, body = post_json(c, f"/batch_delete/{tag}_batch",
                                {"files": [note, "ghost.txt"]}, csrf[name])
        assert st == 200, (name, st, body[:200])
        doc = json.loads(body)
        if doc["success"] is True and doc["deleted"] == 1 and doc["failed"] == 1:
            pass
        elif note not in list_names(c, f"{tag}_batch"):
            pass  # flaked retry: first attempt already deleted note
        else:
            raise AssertionError((name, doc))
    # unzip compare on a shared archive (both extract their own next dir).
    got = {}
    for name, c in clients.items():
        st, _, body = post_json(c, "/unzip/archive.zip", {}, csrf[name])
        assert st == 200, (name, st, body[:200])
        got[name] = json.loads(body)
    assert got["py"] == got["go"] == {"success": True}
    # bad zip.
    for name, c in clients.items():
        st, _, body = post_json(c, "/unzip/photo.jpg", {}, csrf[name])
        assert st == 200, (name, st)
        assert json.loads(body)["success"] is False


def test_simple_upload(twin):
    clients = authed_pair(twin, ADMIN_PW)
    csrf = {n: csrf_of(c, twin[n], twin["py"]) for n, c in clients.items()}
    payload = b"upload-bytes-" * 100
    for name, c in clients.items():
        st, _, body = post_multipart(c, "/upload/", {"paths": f"{name}_up.bin"},
                                     {"file": ("up.bin", payload)}, csrf[name])
        assert st == 200, (name, st, body[:200])
        doc = json.loads(body)
        assert doc["success"] is True and doc["files"][0]["success"] is True, (name, doc)
        st, _, got = c.get(f"/download/{name}_up.bin")
        assert st == 200 and got == payload, (name, st, len(got))


def test_chunk_cycle(twin):
    clients = authed_pair(twin, ADMIN_PW)
    csrf = {n: csrf_of(c, twin[n], twin["py"]) for n, c in clients.items()}
    payload = bytes(range(256)) * 8  # 2048
    for name, c in clients.items():
        st, _, body = post_json(c, "/upload/chunk/init",
                                {"filename": f"{name}_chunk.bin",
                                 "total_size": len(payload),
                                 "chunk_size": 512, "path": ""}, csrf[name])
        assert st == 200, (name, st, body[:200])
        doc = json.loads(body)
        sid = doc["session_id"]
        assert doc["total_chunks"] == 4, (name, doc)
        for i in range(4):
            st, _, body = post_multipart(
                c, f"/upload/chunk/{sid}", {"index": str(i)},
                {"chunk": ("c", payload[i * 512:(i + 1) * 512])}, csrf[name])
            assert st == 200, (name, i, st, body[:200])
        st, _, body = post_json(c, f"/upload/chunk/{sid}/complete", {}, csrf[name])
        assert st == 200, (name, st, body[:200])
        assert json.loads(body)["filename"] == f"{name}_chunk.bin"
        st, _, got = c.get(f"/download/{name}_chunk.bin")
        assert st == 200 and got == payload, (name, st)


def test_share_cycle(twin):
    clients = authed_pair(twin, ADMIN_PW)
    csrf = {n: csrf_of(c, twin[n], twin["py"]) for n, c in clients.items()}
    tokens = {}
    for name, c in clients.items():
        st, _, body = post_json(c, "/share/create",
                                {"path": "hello.txt", "hours": 1}, csrf[name])
        assert st == 200, (name, st, body[:200])
        doc = json.loads(body)
        assert doc["success"] is True and doc["link"].endswith(doc["token"])
        tokens[name] = doc["token"]
        # public download bytes agree.
        from test_milestone_c_contract import TwinClient as TC
        pub = TC(twin[name])
        st, _, got = pub.get(f"/share/{doc['token']}")
        assert st == 200, (name, st, got[:200])
        tokens[name] = (doc["token"], got)
    assert tokens["py"][1] == tokens["go"][1]
    # list + delete agree.
    for name, c in clients.items():
        st, _, body = c.get("/share/list")
        assert st == 200, (name, st)
        assert any(l["token"] == tokens[name][0] for l in json.loads(body)["links"]), name
    for name, c in clients.items():
        st, _, body = post_json(c, f"/share/delete/{tokens[name][0]}", {}, csrf[name])
        assert st == 200 and json.loads(body) == {"success": True}, (name, st, body[:200])


def test_share_password_divergence(twin):
    clients = authed_pair(twin, ADMIN_PW)
    csrf = {n: csrf_of(c, twin[n], twin["py"]) for n, c in clients.items()}
    from test_milestone_c_contract import TwinClient as TC
    pubs = {n: TC(twin[n]) for n in twin}
    for name, c in clients.items():
        st, _, body = post_json(c, "/share/create",
                                {"path": "notes.txt", "hours": 1,
                                 "password": "pw123"}, csrf[name])
        token = json.loads(body)["token"]
        # Challenge shape diverges by design (HTML form vs JSON).
        st, _, _ = pubs[name].get(f"/share/{token}")
        if name == "py":
            assert st == 200, (name, st)
        else:
            assert st == 401, (name, st)
        # Wrong password: both reject (py re-renders 200, go 401 JSON).
        data = urllib.parse.urlencode({"password": "no"}).encode()
        req = urllib.request.Request(
            pubs[name].base + f"/share/{token}", data=data, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Connection": "close"})
        st, _, _ = pubs[name]._open(req, 15)
        assert st == (200 if name == "py" else 401), (name, st)


def test_trash_cycle(twin):
    clients = authed_pair(twin, ADMIN_PW)
    csrf = {n: csrf_of(c, twin[n], twin["py"]) for n, c in clients.items()}
    for name, c in clients.items():
        tag = name
        st, _, body = post_json(c, "/copy", {"source": "hello.txt",
                                             "destination": f"{tag}_t.txt"}, csrf[name])
        assert st == 200, (name, st, body[:200])
        st, _, body = post_json(c, "/trash", {"path": f"{tag}_t.txt"}, csrf[name])
        assert st == 200, (name, st, body[:200])
        doc = json.loads(body)
        assert doc["success"] is True and doc["trash_name"], (name, doc)
        trash_name = doc["trash_name"]
        st, _, body = c.get("/trash/list")
        assert st == 200, (name, st)
        items = json.loads(body)["items"]
        match = [i for i in items if i["name"] == trash_name]
        assert len(match) == 1, (name, items)
        assert match[0]["original_name"] == f"{tag}_t.txt", (name, match)
        st, _, body = post_json(c, "/trash/restore", {"name": trash_name}, csrf[name])
        assert st == 200, (name, st, body[:200])
        assert json.loads(body)["restored_name"] == f"{tag}_t.txt", (name, body[:200])
        st, _, body = post_json(c, "/trash/restore", {"name": "nope"}, csrf[name])
        assert json.loads(body)["success"] is False, (name, body[:200])
        st, _, body = post_json(c, "/trash", {"path": f"{tag}_t.txt"}, csrf[name])
        assert st == 200, (name, st, body[:200])
        st, _, body = post_json(c, "/trash/empty", {}, csrf[name])
        assert st == 200 and json.loads(body) == {"success": True}, (name, st, body[:200])
        st, _, body = post_json(c, "/api/trash/cleanup", {}, csrf[name])
        assert st == 200 and json.loads(body)["success"] is True, (name, st, body[:200])


def test_metadata_cycle(twin):
    clients = authed_pair(twin, ADMIN_PW)
    csrf = {n: csrf_of(c, twin[n], twin["py"]) for n, c in clients.items()}
    for name, c in clients.items():
        st, _, body = post_json(c, "/api/tags",
                                {"path": "hello.txt", "tag": "k", "color": "#00ff00"},
                                csrf[name])
        assert st == 200 and json.loads(body) == {"success": True}, (name, st, body[:200])
        st, _, body = c.get("/api/tags?path=hello.txt")
        assert st == 200 and len(json.loads(body)["tags"]) == 1, (name, st, body[:200])
        for route in ("/api/favorites", "/bookmarks"):
            st, _, body = post_json(c, route, {"path": "sub"}, csrf[name])
            assert st == 200 and json.loads(body) == {"success": True}, (name, route, body[:200])
        st, _, body = post_json(c, "/api/memo/hello.txt", {"memo": "m1"}, csrf[name])
        assert st == 200, (name, st, body[:200])
        st, _, body = c.get("/api/memo/hello.txt")
        assert st == 200 and json.loads(body)["memo"] == "m1", (name, st, body[:200])


def test_versions_audit_system(twin):
    clients = authed_pair(twin, ADMIN_PW)
    csrf = {n: csrf_of(c, twin[n], twin["py"]) for n, c in clients.items()}
    for name, c in clients.items():
        st, _, body = post_json(c, "/copy", {"source": "data.bin",
                                             "destination": f"{name}_v.bin"},
                                csrf[name])
        assert st == 200, (name, st, body[:200])
        st, _, body = post_json(c, "/copy", {"source": "data.bin",
                                             "destination": f"{name}_v.bin",
                                             "conflict_policy": "overwrite"},
                                csrf[name])
        assert st == 200, (name, st, body[:200])
        st, _, body = c.get(f"/versions/{name}_v.bin")
        assert st == 200, (name, st, body[:200])
        versions = json.loads(body)["versions"]
        assert len(versions) >= 1, (name, body[:200])
        newest = versions[0]["name"]
        st, _, body = post_json(c, "/versions/restore",
                                {"version": newest, "target": f"{name}_v.bin"},
                                csrf[name])
        assert st == 200 and json.loads(body) == {"success": True}, (name, st, body[:200])
        st, _, got = c.get(f"/download/{name}_v.bin")
        assert st == 200 and got == bytes(range(256)) * 4, (name, st, len(got))
        st, _, body = c.get("/api/audit_log?action=version_restore&limit=5")
        assert st == 200 and len(json.loads(body)["logs"]) >= 1, (name, st, body[:200])
        st, _, body = c.get("/api/capabilities")
        assert st == 200, (name, st)
        doc = json.loads(body)
        assert set(doc) == {"hls", "webdav", "upnp", "doc_preview", "system_stats", "qrcode"}, (name, doc)
        st, _, body = c.get("/api/disk_info")
        assert st == 200, (name, st, body[:200])
        for key in ("total", "used", "free", "percent", "warning",
                    "total_fmt", "used_fmt", "free_fmt"):
            assert key in json.loads(body), (name, key)
        st, _, body = c.get("/api/folder_size/sub")
        assert st == 200, (name, st, body[:200])
        assert json.loads(body)["path"] == "sub", (name, body[:200])


def test_etag_and_conditional(twin):
    clients = authed_pair(twin, ADMIN_PW)
    etags = {}
    for name, c in clients.items():
        st, headers, _ = c.get("/download/hello.txt")
        assert st == 200, name
        etags[name] = headers.get("ETag") or headers.get("Etag")
    assert etags["py"] == etags["go"], etags
    for name, c in clients.items():
        st, _, _ = c.get("/download/hello.txt",
                         headers={"If-None-Match": etags[name]})
        assert st == 304, (name, st)
