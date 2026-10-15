"""Smoke probe for the live harness itself (not a plan ID)."""

import urllib.parse

from live_harness import seed_files, sha256_bytes


def test_live_harness_login_upload_download(live_server):
    admin = live_server.admin_client()
    assert admin.csrf_token

    payload = bytes(range(256)) * 64  # 16 KiB deterministic
    expect = sha256_bytes(payload)
    status, data = admin.post_multipart(
        "/upload/", {}, [("file", "smoke.bin", payload, "application/octet-stream")]
    )
    assert status == 200, data
    assert data.get("success") is True

    quoted = urllib.parse.quote("smoke.bin", safe="/")
    st, headers, body = admin.get(f"/download/{quoted}")
    assert st == 200, (st, body[:200])
    assert sha256_bytes(body) == expect
    assert (live_server.shared / "smoke.bin").read_bytes() == payload


def test_go_live_harness_login_and_list(go_live_server):
    admin = go_live_server.admin_client()
    assert admin.csrf_token
    status, _, body = admin.get("/api/list/")
    assert status == 200, (status, body[:200])


def test_live_harness_1mib_roundtrip(live_server):
    import os
    import urllib.parse

    admin = live_server.admin_client()
    payload = os.urandom(1024 * 1024)
    expect = sha256_bytes(payload)
    status, data = admin.post_multipart(
        "/upload/", {}, [("file", "big.bin", payload, "application/octet-stream")]
    )
    assert status == 200, data
    quoted = urllib.parse.quote("big.bin", safe="/")
    st, _, body = admin.get(f"/download/{quoted}")
    assert st == 200, (st, body[:200])
    assert sha256_bytes(body) == expect


def test_go_live_harness_1mib_roundtrip(go_live_server):
    import os
    import urllib.parse

    from live_harness import sha256_bytes as _sha

    admin = go_live_server.admin_client()
    payload = os.urandom(1024 * 1024)
    expect = _sha(payload)
    status, data = admin.post_multipart(
        "/upload/", {}, [("file", "big.bin", payload, "application/octet-stream")]
    )
    assert status == 200, data
    quoted = urllib.parse.quote("big.bin", safe="/")
    st, _, body = admin.get(f"/download/{quoted}")
    assert st == 200, (st, body[:200])
    assert _sha(body) == expect
