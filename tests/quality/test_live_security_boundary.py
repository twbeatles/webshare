"""Phase 3 -- live security-boundary invariants.

Same loopback servers, hostile inputs only inside the isolated roots:
role matrix, traversal/encoding/symlink/ZIP-name boundaries, share
brute-force blocking, and secret hygiene (no plaintext secrets in
artifacts or API echoes).
"""

import os
import urllib.parse

from live_harness import GUEST_PW, seed_files, sha256_bytes


def q(path: str) -> str:
    return urllib.parse.quote(path, safe="/")


# --------------------------------------------------------------------------
# roles x mutating endpoints: guest 403, anonymous denied, admin allowed
# --------------------------------------------------------------------------

_MUTATING = [
    ("POST", "/mkdir/", {"name": "d"}),
    ("POST", "/delete/victim.txt", {}),
    ("POST", "/rename/victim.txt", {"name": "r.txt"}),
    ("POST", "/copy", {"source": "victim.txt", "destination": "c.txt"}),
    ("POST", "/move", {"source": "victim.txt", "destination": "m.txt"}),
    ("POST", "/trash", {"path": "victim.txt"}),
    ("POST", "/share/create", {"path": "victim.txt", "hours": 1}),
    ("POST", "/versions/restore", {"version": "x", "target": "victim.txt"}),
]


def test_security_role_matrix_mutations(live_server):
    admin = live_server.admin_client()
    guest = live_server.client()
    guest.login(GUEST_PW)
    seed_files(live_server.shared, {"victim.txt": b"v" * 128})

    from live_harness import LiveClient

    anon = LiveClient(live_server.base_url)
    for method, path, body in _MUTATING:
        status, _ = guest.post_json(path, body)
        assert status == 403, (path, status)
        status, _, _ = anon._request("POST", path, body=b"{}",
                                     content_type="application/json",
                                     follow_redirects=False)
        assert status in (302, 401, 403), (path, status)

    # admin is not locked out by the same policy
    status, data = admin.post_json("/mkdir/", {"name": "sec_d"})
    assert status == 200, (status, data)


def test_security_guest_cannot_elevate_via_admin_apis(live_server):
    guest = live_server.client()
    guest.login(GUEST_PW)
    ajax = {"X-Requested-With": "XMLHttpRequest"}
    for path in ("/api/users", "/api/audit_log", "/trash/list",
                 "/versions/restore"):
        if path == "/versions/restore":
            status, _ = guest.post_json(path, {"version": "x", "target": "y"})
        else:
            status, _ = guest.get_json(path, headers=ajax)
        assert status in (401, 403), (path, status)
    # browser-style GET without XHR must redirect to login, never 200+data
    status, headers, body = guest.get("/trash/list", follow_redirects=False)
    assert status == 302, (status, body[:100])


def test_security_share_bruteforce_blocked(live_server):
    from config import MAX_LOGIN_ATTEMPTS

    admin = live_server.admin_client()
    payload = os.urandom(2048)
    seed_files(live_server.shared, {"locked.bin": payload})
    status, created = admin.post_json(
        "/share/create",
        {"path": "locked.bin", "hours": 24, "password": "right-pw",
         "max_downloads": 0},
    )
    assert status == 200 and created.get("success"), created
    link = f"/share/{created['token']}"

    from live_harness import LiveClient

    for _ in range(int(MAX_LOGIN_ATTEMPTS)):
        anon = LiveClient(live_server.base_url)
        st, _h, body = anon.post_form(link, {"password": "wrong"})
        assert st == 200, st
        assert sha256_bytes(body) != sha256_bytes(payload)
    blocked = LiveClient(live_server.base_url)
    st, _h, body = blocked.get(link)
    assert st == 429, st
    assert sha256_bytes(body) != sha256_bytes(payload)


def test_security_protected_system_paths_denied(live_server):
    admin = live_server.admin_client()
    for evil in (".webshare_trash", ".webshare_trash.json", ".upload_temp/x",
                 "sub/.webshare_versions/y"):
        status, _ = admin.post_json("/trash", {"path": evil})
        assert status in (400, 403, 404), (evil, status)
        status, _ = admin.post_json(
            "/share/create", {"path": evil, "hours": 1})
        assert status in (400, 403), (evil, status)


def test_security_double_encoding_and_backslash_dual(
    live_server, go_live_server, tmp_path
):
    secret = tmp_path / "sec_out.txt"
    secret.write_bytes(b"ESCAPED-SECRET")
    for admin, tag in (
        (live_server.admin_client(), "py"),
        (go_live_server.admin_client(), "go"),
    ):
        for evil in ("..%252fsec_out.txt", "..%5csec_out.txt",
                     "%2e%2e%2fsec_out.txt", "a%2f..%2f..%2fsec_out.txt"):
            st, _h, body = admin.get(f"/download/{evil}")
            assert b"ESCAPED-SECRET" not in body, (tag, evil, st)
        for endpoint in ("/api/list/", "/file_info/"):
            st, payload = admin.get_json(f"{endpoint}{evil}")
            assert st != 200 or "sec_out" not in str(payload), (tag, evil, st)


def test_security_zip_member_names_cannot_escape(live_server, tmp_path):
    import io
    import zipfile

    admin = live_server.admin_client()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("..\\win_evil.txt", b"X")
        zf.writestr("sub/../../nix_evil.txt", b"Y")
        zf.writestr("/abs_evil.txt", b"Z")
        zf.writestr("ok.txt", b"fine")
    status, data = admin.post_multipart(
        "/upload/", {}, [("file", "names.zip", buf.getvalue(), "application/zip")]
    )
    assert status == 200, data
    status, data = admin.post_json("/unzip/names.zip", {})
    assert status == 400, (status, data)
    for name in ("win_evil.txt", "nix_evil.txt", "abs_evil.txt"):
        assert not (live_server.shared / name).exists(), name
        assert not (tmp_path / name).exists(), name


def test_security_no_secret_echo_in_apis_or_artifacts(live_server):
    admin = live_server.admin_client()
    seed_files(live_server.shared, {"s.txt": b"data"})
    password = "sup3r-secret-pw"
    status, created = admin.post_json(
        "/share/create",
        {"path": "s.txt", "hours": 1, "password": password, "max_downloads": 0},
    )
    assert status == 200 and created.get("success"), created
    assert password not in str(created), "password echoed in create response"

    status, links = admin.get_json("/share/list")
    assert status == 200, status
    assert password not in str(links), "password echoed in share list"

    status, audit = admin.get_json("/api/audit_log")
    assert status == 200, status
    assert password not in str(audit), "password echoed in audit log"
    assert created["token"] not in str(audit), "full token echoed in audit log"
