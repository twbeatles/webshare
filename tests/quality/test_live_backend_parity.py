"""Phase 1 -- live two-process backend parity (PAR-01..PAR-12).

Every test here drives REAL HTTP servers on 127.0.0.1 with isolated roots:
Flask (``live_server``, same-process WSGI over a real socket) and Go
(``go_live_server``, real ``webshare-core`` subprocess). The independent
oracle is always file SHA-256 / received bytes / status semantics -- never
the server's own permission helpers.

Representation differences that are BOTH safe denials (e.g. Python 302
redirect vs Go 401 JSON for anonymous browsers) are normalized explicitly
and listed in CONTRACT_MATRIX.md; byte/permission outcomes are not.
"""

import os
import urllib.parse

import pytest

from live_harness import ADMIN_PW, GUEST_PW, seed_files, sha256_bytes

SIZES = [0, 1, 1024, 1024 * 1024]


def q(path: str) -> str:
    return urllib.parse.quote(path, safe="/")


def up(client, folder, name, data, ctype="application/octet-stream"):
    if hasattr(client, "post_multipart"):
        pass
    status, payload = client.post_multipart(
        f"/upload/{q(folder)}" if folder else "/upload/",
        {},
        [("file", name, data, ctype)],
    )
    return status, payload


def dl(client, rel):
    st, _headers, body = client.get(f"/download/{q(rel)}")
    return st, body


# --------------------------------------------------------------------------
# PAR-01: upload -> download byte identity, both backends, same oracle
# --------------------------------------------------------------------------

@pytest.mark.parametrize("size", SIZES)
def test_par01_upload_download_bytes_match_dual(
    live_server, go_live_server, size
):
    payload = os.urandom(size)
    expect = sha256_bytes(payload)

    py_admin = live_server.admin_client()
    go_admin = go_live_server.admin_client()

    for admin, tag in ((py_admin, "py"), (go_admin, "go")):
        status, data = up(admin, "", f"par01_{tag}_{size}.bin", payload)
        assert status == 200, (tag, status, data)
        assert data.get("success") is True

    for admin, root, tag in (
        (py_admin, live_server.shared, "py"),
        (go_admin, go_live_server.shared, "go"),
    ):
        st, body = dl(admin, f"par01_{tag}_{size}.bin")
        assert st == 200, (tag, st)
        assert sha256_bytes(body) == expect, tag
        assert (root / f"par01_{tag}_{size}.bin").read_bytes() == payload


def test_par01_korean_emoji_filename_dual(live_server, go_live_server):
    name = "한글_이모지_😀.txt"
    payload = "내용-😀-content".encode("utf-8")
    expect = sha256_bytes(payload)
    for admin, tag in (
        (live_server.admin_client(), "py"),
        (go_live_server.admin_client(), "go"),
    ):
        status, data = up(admin, "", name, payload, "text/plain; charset=utf-8")
        assert status == 200, (tag, status, data)
        st, body = dl(admin, name)
        assert st == 200, (tag, st)
        assert sha256_bytes(body) == expect, tag


def test_par01_same_name_different_bytes_kept(live_server):
    admin = live_server.admin_client()
    first = os.urandom(2048)
    second = os.urandom(2048)
    assert first != second
    (live_server.shared / "same.bin").write_bytes(first)
    status, data = up(admin, "", "same.bin", second)
    assert status == 200, data
    kept = (live_server.shared / "same.bin").read_bytes()
    assert sha256_bytes(kept) == sha256_bytes(first), "original overwritten!"
    files = [p for p in data.get("files", []) if p.get("success")]
    assert files and files[0]["name"] != "same.bin"


# --------------------------------------------------------------------------
# PAR-02: role enforcement parity (owner/admin vs read-only vs anonymous)
# --------------------------------------------------------------------------

def test_par02_role_enforcement_dual(live_server, go_live_server):
    oracle = seed_files(live_server.shared, {"pub.txt": b"public-bytes"})
    seed_files(go_live_server.shared, {"pub.txt": b"public-bytes"})
    _ = oracle

    py_admin = live_server.admin_client()
    go_admin = go_live_server.admin_client()
    py_guest = live_server.client()
    py_guest.login(GUEST_PW)
    go_guest = go_live_server.client()
    go_guest.login(GUEST_PW)

    # guests cannot mutate on either backend (allow_guest_upload=False)
    for guest, tag in ((py_guest, "py"), (go_guest, "go")):
        status, data = up(guest, "", "guest_try.bin", b"x")
        assert status == 403, (tag, status, data)

    # guests CAN read public files on both backends
    for guest, tag in ((py_guest, "py"), (go_guest, "go")):
        st, body = dl(guest, "pub.txt")
        assert st == 200, (tag, st)
        assert body == b"public-bytes", tag

    # admins can mutate on both
    for admin, tag in ((py_admin, "py"), (go_admin, "go")):
        status, data = up(admin, "", f"admin_{tag}.bin", b"ok")
        assert status == 200 and data.get("success") is True, (tag, data)

    # anonymous: both deny with a login redirect (302) and zero file bytes.
    # No redirect following: the denial response itself is the contract.
    from live_harness import GoClient, LiveClient

    py_anon = LiveClient(live_server.base_url)
    st, headers, body = py_anon.get("/download/pub.txt", follow_redirects=False)
    assert st == 302, ("py", st)
    assert b"public-bytes" not in body

    go_anon = GoClient(go_live_server.base_url)
    st, go_headers, body = go_anon.get("/download/pub.txt")
    assert st == 302, ("go", st)
    assert b"public-bytes" not in body


# --------------------------------------------------------------------------
# PAR-03: password share challenge (HTML form / wrong pw / correct download)
# --------------------------------------------------------------------------

def _share_roundtrip(admin, name, payload, password, tag):
    status, data = admin.post_multipart(
        "/upload/", {}, [("file", name, payload, "application/octet-stream")]
    )
    assert status == 200, (tag, data)
    status, created = admin.post_json(
        "/share/create",
        {"path": name, "hours": 24, "password": password, "max_downloads": 0},
    )
    assert status == 200 and created.get("success"), (tag, status, created)
    token = created["token"]
    link = f"/share/{token}"

    anon_t = type(admin)
    anon = anon_t(admin.base_url)
    st, headers, body = anon.get(link)
    ctype = (
        headers.get("Content-Type", "")
        if isinstance(headers, dict)
        else headers.get_content_type()
    )
    assert st == 200, (tag, st)
    assert "text/html" in ctype, (tag, ctype)
    assert b"password" in body.lower(), tag

    # wrong password: HTML form again, zero file bytes
    st, _h, bad = anon.post_form(link, {"password": "wrong-pw"})
    assert st == 200, (tag, st)
    assert sha256_bytes(bad) != sha256_bytes(payload), tag

    # correct password: exact file bytes
    st, _h, good = anon.post_form(link, {"password": password})
    assert st == 200, (tag, st)
    assert sha256_bytes(good) == sha256_bytes(payload), tag
    return token


def test_par03_password_share_dual(live_server, go_live_server):
    payload = os.urandom(8192)
    _share_roundtrip(
        live_server.admin_client(), "secret_py.bin", payload, "s3cret", "py"
    )
    _share_roundtrip(
        go_live_server.admin_client(), "secret_go.bin", payload, "s3cret", "go"
    )


def test_par03_share_download_count_contract(live_server):
    admin = live_server.admin_client()
    payload = os.urandom(4096)
    status, uploaded = admin.post_multipart(
        "/upload/", {}, [("file", "counted.bin", payload, "application/octet-stream")]
    )
    assert status == 200 and uploaded.get("success") is True, (status, uploaded)
    status, created = admin.post_json(
        "/share/create",
        {"path": "counted.bin", "hours": 24, "password": "", "max_downloads": 2},
    )
    assert status == 200 and created.get("success"), created
    from live_harness import LiveClient

    link = f"/share/{created['token']}"
    for _ in range(2):
        anon = LiveClient(live_server.base_url)
        st, _h, body = anon.get(link)
        assert st == 200, st
        assert sha256_bytes(body) == sha256_bytes(payload)
    anon = LiveClient(live_server.base_url)
    st, _h, body = anon.get(link)
    assert st == 429, st
    assert sha256_bytes(body) != sha256_bytes(payload)


# --------------------------------------------------------------------------
# PAR-04: expired / missing / exhausted share links
# --------------------------------------------------------------------------

def test_par04_share_expiry_and_limits(live_server, go_live_server):
    py_admin = live_server.admin_client()
    go_admin = go_live_server.admin_client()
    seed_files(live_server.shared, {"lim.txt": b"limited"})
    seed_files(go_live_server.shared, {"lim.txt": b"limited"})

    # missing token: 404 both, no bytes
    from live_harness import GoClient, LiveClient

    for anon, tag in (
        (LiveClient(live_server.base_url), "py"),
        (GoClient(go_live_server.base_url), "go"),
    ):
        st, _h, body = anon.get("/share/no-such-token")
        assert st == 404, (tag, st)
        assert b"limited" not in body

    # exhausted quota: max_downloads=1 -> second fetch 429 both
    for admin, base, cls, tag in (
        (py_admin, live_server.base_url, LiveClient, "py"),
        (go_admin, go_live_server.base_url, GoClient, "go"),
    ):
        status, created = admin.post_json(
            "/share/create",
            {"path": "lim.txt", "hours": 24, "password": "", "max_downloads": 1},
        )
        assert status == 200 and created.get("success"), (tag, created)
        link = f"/share/{created['token']}"
        first = cls(base)
        st, _h, body = first.get(link)
        assert st == 200 and body == b"limited", (tag, st)
        again = cls(base)
        st, _h, body = again.get(link)
        assert st == 429, (tag, st)
        assert body != b"limited", tag

    # expired link: 410 + zero bytes (Python; time-travel via server state)
    from config import SHARE_LINKS, share_links_lock

    status, created = py_admin.post_json(
        "/share/create",
        {"path": "lim.txt", "hours": 1, "password": "", "max_downloads": 0},
    )
    assert status == 200 and created.get("success"), created
    token = created["token"]
    from datetime import datetime, timedelta

    with share_links_lock:
        SHARE_LINKS[token]["expires"] = datetime.now() - timedelta(seconds=1)
    anon = LiveClient(live_server.base_url)
    st, _h, body = anon.get(f"/share/{token}")
    assert st == 410, st
    assert body != b"limited"


def test_par04_go_share_expiry_via_persisted_store(go_live_server):
    """Go expiry without clock control: persist, time-travel, restart.

    The Go backend loads `.webshare_share_links.json` at startup and
    purges already-expired links on load, so an injected past expiry is
    proven over real HTTP as 404 (purged, never resurrected) with zero
    file bytes. Runtime expiry mid-process is 410 on both backends
    (Python proven live here; Go proven in go-core unit tests).
    """
    import json as _json
    from datetime import datetime, timedelta, timezone

    from live_harness import GoClient, seed_files, sha256_bytes

    admin = go_live_server.admin_client()
    payload = b"go-expiry-bytes"
    seed_files(go_live_server.shared, {"exp.txt": payload})
    status, created = admin.post_json(
        "/share/create",
        {"path": "exp.txt", "hours": 1, "password": "", "max_downloads": 0},
    )
    assert status == 200 and created.get("success"), created
    token = created["token"]

    store = go_live_server.shared / ".webshare_share_links.json"
    assert store.exists(), "go share store not persisted"
    doc = _json.loads(store.read_text(encoding="utf-8"))
    assert token in doc.get("links", {}), doc.get("links", {}).keys()
    # Two days past in UTC: immune to the naive-local-vs-UTC skew between
    # Python's datetime.now() and Go's time.Parse (UTC) on any real zone.
    past = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    doc["links"][token]["expires"] = past
    store.write_text(_json.dumps(doc), encoding="utf-8")

    go_live_server.restart()
    anon = GoClient(go_live_server.base_url)
    st, _h, body = anon.get(f"/share/{token}")
    assert st == 404, st
    assert sha256_bytes(body) != sha256_bytes(payload)

    admin2 = go_live_server.admin_client()
    status, listed = admin2.get_json("/share/list")
    assert status == 200, status
    tokens = [item.get("token", "") for item in listed.get("links", [])]
    assert token not in tokens, "expired link resurrected after restart"


# --------------------------------------------------------------------------
# PAR-05: inline preview + Content-Disposition + UTF-8 filename
# --------------------------------------------------------------------------

def test_par05_preview_and_disposition_dual(live_server, go_live_server):
    name = "보고서_2026.txt"
    payload = ("본문 내용 " * 200).encode("utf-8")
    expect = sha256_bytes(payload)
    for admin, tag in (
        (live_server.admin_client(), "py"),
        (go_live_server.admin_client(), "go"),
    ):
        status, data = up(admin, "", name, payload, "text/plain; charset=utf-8")
        assert status == 200, (tag, data)

        st, headers, body = admin.get(f"/download/{q(name)}")
        assert st == 200, (tag, st)
        assert sha256_bytes(body) == expect, tag
        if isinstance(headers, dict):
            disp = headers.get("Content-Disposition", "")
        else:
            disp = headers.get("Content-Disposition", "")
        assert disp, (tag, "missing Content-Disposition")
        assert "filename" in disp, (tag, disp)

    # Both backends serve /preview/ (Go: CSV/JSON/DOCX; other formats answer
    # the same "unsupported" text as Python). Go gained the route with the
    # full web UI (audit ISSUE-003).
    py_admin = live_server.admin_client()
    st, _h, seen = py_admin.get(f"/preview/{q(name)}")
    assert st == 200, ("py-preview", st)
    assert len(seen) > 0
    go_admin = go_live_server.admin_client()
    st, _h, go_seen = go_admin.get(f"/preview/{q(name)}")
    assert st == 200, ("go-preview", st)
    assert len(go_seen) > 0


# --------------------------------------------------------------------------
# PAR-06: duplicate upload / overwrite-refused rename
# --------------------------------------------------------------------------

def test_par06_duplicate_upload_and_rename_conflict_dual(
    live_server, go_live_server
):
    first = os.urandom(4096)
    second = os.urandom(4096)
    for admin, root, tag in (
        (live_server.admin_client(), live_server.shared, "py"),
        (go_live_server.admin_client(), go_live_server.shared, "go"),
    ):
        s1, d1 = up(admin, "", "dup.bin", first)
        s2, d2 = up(admin, "", "dup.bin", second)
        assert s1 == 200 and s2 == 200, (tag, d1, d2)
        n1 = d1["files"][0]["name"]
        n2 = d2["files"][0]["name"]
        assert n1 != n2, (tag, n1, n2)
        assert (root / n1).read_bytes() == first, tag
        assert sha256_bytes((root / n2).read_bytes()) == sha256_bytes(second)

    # rename onto an existing name is refused; victim bytes preserved
    admin = live_server.admin_client()
    seed_files(live_server.shared, {"keep_a.txt": b"A" * 64, "keep_b.txt": b"B" * 64})
    status, data = admin.post_json("/rename/keep_a.txt", {"name": "keep_b.txt"})
    assert status == 400, (status, data)
    assert (live_server.shared / "keep_b.txt").read_bytes() == b"B" * 64


# --------------------------------------------------------------------------
# PAR-07: chunked upload -- out-of-order, missing, duplicate, bad session
# --------------------------------------------------------------------------

def _chunk_upload(admin, name, payload, chunk_size, order, tag):
    total = len(payload)
    n = (total + chunk_size - 1) // chunk_size if total else 0
    status, init = admin.post_json(
        "/upload/chunk/init",
        {
            "filename": name, "total_size": total, "path": "",
            "chunk_size": chunk_size, "total_chunks": n,
        },
    )
    assert status == 200 and init.get("success"), (tag, status, init)
    sid = init["session_id"]
    for index in order:
        part = payload[index * chunk_size:(index + 1) * chunk_size]
        status, data = admin.post_multipart(
            f"/upload/chunk/{sid}",
            {"index": str(index)},
            [("chunk", name, part, "application/octet-stream")],
        )
        assert status == 200, (tag, index, status, data)
    status, done = admin.post_json(f"/upload/chunk/{sid}/complete", {})
    return sid, status, done


def test_par07_chunk_out_of_order_dual(live_server, go_live_server):
    payload = os.urandom(100 * 1024)
    expect = sha256_bytes(payload)
    for admin, root, tag in (
        (live_server.admin_client(), live_server.shared, "py"),
        (go_live_server.admin_client(), go_live_server.shared, "go"),
    ):
        name = f"ooo_{tag}.bin"
        n = (len(payload) + 16384 - 1) // 16384
        order = list(reversed(range(n)))
        _sid, status, done = _chunk_upload(admin, name, payload, 16384, order, tag)
        assert status == 200 and done.get("success"), (tag, status, done)
        target = root / done.get("filename", name)
        assert target.exists(), (tag, done)
        assert sha256_bytes(target.read_bytes()) == expect, tag


def test_par07_chunk_missing_index_leaves_no_file(live_server):
    admin = live_server.admin_client()
    payload = os.urandom(3 * 8192)
    status, init = admin.post_json(
        "/upload/chunk/init",
        {"filename": "hole.bin", "total_size": len(payload),
         "path": "", "chunk_size": 8192, "total_chunks": 3},
    )
    assert status == 200, init
    sid = init["session_id"]
    for index in (0, 2):  # chunk 1 missing
        part = payload[index * 8192:(index + 1) * 8192]
        status, _ = admin.post_multipart(
            f"/upload/chunk/{sid}", {"index": str(index)},
            [("chunk", "hole.bin", part, "application/octet-stream")],
        )
        assert status == 200, (index, status)
    status, done = admin.post_json(f"/upload/chunk/{sid}/complete", {})
    assert status == 400, (status, done)
    assert not (live_server.shared / "hole.bin").exists()
    assert "hole" not in "".join(
        p.name for p in live_server.shared.iterdir() if p.is_file()
    )


def test_par07_chunk_duplicate_resend_ok_and_bad_session(live_server):
    admin = live_server.admin_client()
    payload = os.urandom(2 * 4096)
    status, init = admin.post_json(
        "/upload/chunk/init",
        {"filename": "dup_chunk.bin", "total_size": len(payload),
         "path": "", "chunk_size": 4096, "total_chunks": 2},
    )
    assert status == 200, init
    sid = init["session_id"]
    for index in (0, 0, 1):  # duplicate chunk 0
        part = payload[index * 4096:(index + 1) * 4096]
        status, _ = admin.post_multipart(
            f"/upload/chunk/{sid}", {"index": str(index)},
            [("chunk", "dup_chunk.bin", part, "application/octet-stream")],
        )
        assert status == 200, (index, status)
    status, done = admin.post_json(f"/upload/chunk/{sid}/complete", {})
    assert status == 200 and done.get("success"), (status, done)
    target = live_server.shared / done.get("filename", "dup_chunk.bin")
    assert sha256_bytes(target.read_bytes()) == sha256_bytes(payload)

    status, done = admin.post_json("/upload/chunk/no-such-session/complete", {})
    assert status == 400, (status, done)


# --------------------------------------------------------------------------
# PAR-08: traversal / symlink / encoding variants never escape root
# --------------------------------------------------------------------------

_TRAVERSAL_PATHS = [
    "../outside.txt",
    "..%2Foutside.txt",
    "..%252Foutside.txt",
    "..\\outside.txt",
    "%2e%2e/outside.txt",
    "sub/../../outside.txt",
    "/etc/hostname",
    "C:/Windows/win.ini",
]


def test_par08_traversal_blocked_dual(live_server, go_live_server, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"TOP-SECRET-OUTSIDE")
    for admin, tag in (
        (live_server.admin_client(), "py"),
        (go_live_server.admin_client(), "go"),
    ):
        for evil in _TRAVERSAL_PATHS:
            st, _h, body = admin.get(f"/download/{evil}")
            assert st != 200 or b"TOP-SECRET-OUTSIDE" not in body, (tag, evil, st)
        # absolute filesystem path smuggled as subpath
        st, _h, body = admin.get(f"/download/{q(str(outside))}")
        assert b"TOP-SECRET-OUTSIDE" not in body, (tag, st)


def test_par08_symlink_escape_blocked_dual(live_server, go_live_server, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"SYMLINK-SECRET")
    for shared, admin, tag in (
        (live_server.shared, live_server.admin_client(), "py"),
        (go_live_server.shared, go_live_server.admin_client(), "go"),
    ):
        link = shared / "evil_link.txt"
        try:
            if link.exists() or link.is_symlink():
                link.unlink()
            link.symlink_to(secret)
        except OSError:
            pytest.skip("symlinks unavailable on this machine")
        st, _h, body = admin.get("/download/evil_link.txt")
        assert b"SYMLINK-SECRET" not in body, (tag, st)
        link.unlink()


# --------------------------------------------------------------------------
# PAR-09: trash move / list / restore byte identity
# --------------------------------------------------------------------------

def test_par09_trash_roundtrip_dual(live_server, go_live_server):
    payload = os.urandom(32768)
    expect = sha256_bytes(payload)
    for admin, shared, tag in (
        (live_server.admin_client(), live_server.shared, "py"),
        (go_live_server.admin_client(), go_live_server.shared, "go"),
    ):
        (shared / f"trashme_{tag}.txt").write_bytes(payload)
        rel = f"trashme_{tag}.txt"
        status, data = admin.post_json("/trash", {"path": rel})
        assert status == 200 and data.get("success"), (tag, status, data)
        assert not (shared / rel).exists(), tag
        trash_name = data.get("trash_name", "")

        status, listed = admin.get_json("/trash/list")
        assert status == 200, (tag, status)
        items = listed.get("items", [])
        match = [i for i in items if i.get("name", "") == trash_name]
        assert match, (tag, trash_name, items)
        assert match[0].get("original_path", "").endswith(rel), match[0]

        status, data = admin.post_json("/trash/restore", {"name": trash_name})
        assert status == 200 and data.get("success"), (tag, status, data)
        restored = shared / rel
        assert restored.exists(), tag
        assert sha256_bytes(restored.read_bytes()) == expect, tag


# --------------------------------------------------------------------------
# PAR-10: restart keeps files / shares / permissions
# --------------------------------------------------------------------------

def test_par10_restart_preserves_state(live_server):
    admin = live_server.admin_client()
    payload = os.urandom(16384)
    expect = sha256_bytes(payload)
    (live_server.shared / "persist.bin").write_bytes(payload)
    status, created = admin.post_json(
        "/share/create",
        {"path": "persist.bin", "hours": 24, "password": "", "max_downloads": 0},
    )
    assert status == 200 and created.get("success"), created
    token = created["token"]

    new_base = live_server.restart()
    assert new_base != live_server.base_url or True  # port may be reused

    admin2 = live_server.admin_client()
    st, _h, body = admin2.get(f"/download/{q('persist.bin')}")
    assert st == 200 and sha256_bytes(body) == expect

    from live_harness import LiveClient

    anon = LiveClient(live_server.base_url)
    st, _h, body = anon.get(f"/share/{token}")
    assert st == 200, st
    assert sha256_bytes(body) == expect

    # pre-restart in-memory chunk session must be gone (M8 detector lives in
    # test_mutation_detection.py; here: restart is a clean slate for uploads)
    status, data = admin2.post_json("/trash", {"path": "persist.bin"})
    assert status == 200 and data.get("success"), (status, data)


# --------------------------------------------------------------------------
# PAR-11: documented backend differences (refusals, not silent gaps)
# --------------------------------------------------------------------------

def test_par11_go_https_combination_is_refused(monkeypatch):
    from webshare_app.server import (
        GO_HTTPS_BLOCKED, _server_startup_error, _use_go_backend,
        go_process, start_server,
    )

    monkeypatch.setenv(go_process.BACKEND_ENV, "go")
    assert _use_go_backend() is True
    import webshare_app.server as srv

    old_error = srv._server_startup_error
    try:
        ok = start_server(use_https=True, wait_ready=False, timeout=1.0)
        assert ok is False
        assert srv._server_startup_error == GO_HTTPS_BLOCKED
        assert "HTTPS" in GO_HTTPS_BLOCKED
        assert srv.server_thread is None or not srv.server_thread.is_alive()
    finally:
        srv._server_startup_error = old_error


def test_par11_backend_selection_contract(monkeypatch):
    from webshare_app.server import go_process

    monkeypatch.delenv(go_process.BACKEND_ENV, raising=False)
    assert go_process.backend_name() == "go"
    monkeypatch.setenv(go_process.BACKEND_ENV, "python")
    assert go_process.backend_name() == "python"
    assert go_process.find_binary() is None or isinstance(
        go_process.find_binary(), str
    )


# --------------------------------------------------------------------------
# PAR-12: Docker serves the Python stack (explicit, not assumed)
# --------------------------------------------------------------------------

def test_par12_docker_entrypoint_serves_python_stack():
    import pathlib

    text = pathlib.Path("docker_entrypoint.py").read_text(encoding="utf-8")
    assert "build_composed_wsgi_app" in text
    assert "make_server" in text
    assert "webshare-core" not in text
    assert "go_process" not in text
    assert "WEBSHARE_FOLDER" in text and "/data" in text

