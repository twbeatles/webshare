"""Phase 4 -- mutation detectors (M1..M10).

Each test below is the tripwire for exactly one semantic mutant described
in the verification plan. Alone they assert real contracts; under
``scripts/run_mutation_check.py`` each MUST turn RED when its mutant is
applied and GREEN again after revert. A detector that stays GREEN under
its mutant is recorded SURVIVED, not passed.
"""

import os
import urllib.parse

import pytest

from live_harness import seed_files, sha256_bytes


def q(path: str) -> str:
    return urllib.parse.quote(path, safe="/")


def _init(admin, filename, total, chunk_size=4096):
    n = (total + chunk_size - 1) // chunk_size if total else 0
    status, init = admin.post_json(
        "/upload/chunk/init",
        {"filename": filename, "total_size": total, "path": "",
         "chunk_size": chunk_size, "total_chunks": n},
    )
    assert status == 200 and init.get("success"), (status, init)
    return init["session_id"], n


def _send(admin, sid, name, index, data):
    return admin.post_multipart(
        f"/upload/chunk/{sid}", {"index": str(index)},
        [("chunk", name, data, "application/octet-stream")],
    )


# M1: chunk index range validation detached -> out-of-range send accepted.
def test_m1_chunk_index_range_rejected(live_server):
    admin = live_server.admin_client()
    sid, n = _init(admin, "m1.bin", 2 * 1024, chunk_size=1024)
    assert n == 2
    status, data = _send(admin, sid, "m1.bin", 2, b"z" * 1024)
    assert status == 400, (status, data)


# M2: COMPLETING merge/cancel guard detached -> double entry accepted.
def test_m2_completing_guard_rejects_reentry(live_server):
    from config import upload_session_lock
    from webshare_app.services.upload_service import (
        UPLOAD_SESSIONS,
        UPLOAD_STATUS_COMPLETING,
    )

    admin = live_server.admin_client()
    payload = os.urandom(2 * 1024)
    sid, _n = _init(admin, "m2.bin", len(payload), chunk_size=1024)
    for index in (0, 1):
        status, _ = _send(admin, sid, "m2.bin", index,
                           payload[index * 1024:(index + 1) * 1024])
        assert status == 200
    with upload_session_lock:
        UPLOAD_SESSIONS[sid]["status"] = UPLOAD_STATUS_COMPLETING
    try:
        status, _ = admin.post_json(f"/upload/chunk/{sid}/complete", {})
        assert status == 409, status
    finally:
        with upload_session_lock:
            if UPLOAD_SESSIONS.get(sid) is not None:
                UPLOAD_SESSIONS[sid]["status"] = "active"


# M3: merge writes nothing yet reports success.
def test_m3_complete_writes_real_bytes(live_server):
    admin = live_server.admin_client()
    payload = os.urandom(2 * 2048)
    sid, _n = _init(admin, "m3.bin", len(payload), chunk_size=2048)
    for index in (0, 1):
        status, _ = _send(admin, sid, "m3.bin", index,
                           payload[index * 2048:(index + 1) * 2048])
        assert status == 200
    status, done = admin.post_json(f"/upload/chunk/{sid}/complete", {})
    assert status == 200 and done.get("success"), (status, done)
    target = live_server.shared / done.get("filename", "m3.bin")
    assert sha256_bytes(target.read_bytes()) == sha256_bytes(payload)


# M4: root validation / permission check detached -> escape readable.
def test_m4_absolute_path_escape_blocked(live_server, tmp_path):
    secret = tmp_path / "m4_secret.txt"
    secret.write_bytes(b"M4-OUTSIDE-SECRET")
    admin = live_server.admin_client()
    st, _h, body = admin.get(f"/download/{q(str(secret))}")
    assert b"M4-OUTSIDE-SECRET" not in body, st
    assert st in (302, 400, 403, 404), st


# M5: download-count reservation detached -> quota bypassed under race.
# Sequential double-fetch is masked by the redundant pre-check gate, so the
# detector hammers the link concurrently: only the atomic reserve can hold
# max_downloads at exactly 1. Under the mutant the stale gate lets the whole
# burst through and every reservation succeeds.
def test_m5_share_quota_atomic_under_burst(live_server):
    import hashlib as _hl
    import threading

    from live_harness import LiveClient

    admin = live_server.admin_client()
    payload = os.urandom(4096)
    file_hash = sha256_bytes(payload)
    admin.post_multipart(
        "/upload/", {}, [("file", "m5.bin", payload, "application/octet-stream")]
    )
    status, created = admin.post_json(
        "/share/create",
        {"path": "m5.bin", "hours": 24, "password": "", "max_downloads": 1},
    )
    assert status == 200 and created.get("success"), created
    link = f"/share/{created['token']}"
    base = live_server.base_url
    results = []
    start = threading.Event()
    clients = [LiveClient(base, timeout=30) for _ in range(8)]

    def grab(slot):
        start.wait(timeout=15)
        try:
            st, _h, body = clients[slot].get(link)
            results.append((_hl.sha256(body).hexdigest() == file_hash, st))
        except Exception:
            results.append((False, "error"))

    threads = [
        threading.Thread(target=grab, args=(slot,)) for slot in range(8)
    ]
    for t in threads:
        t.start()
    start.set()
    for t in threads:
        t.join(timeout=60)
    assert len(results) == 8
    delivered = sum(1 for is_file, _ in results if is_file)
    assert delivered == 1, [st for _, st in results]


# M6: trash restore reports success without restoring bytes.
def test_m6_restore_returns_original_bytes(live_server):
    admin = live_server.admin_client()
    payload = os.urandom(4096)
    seed_files(live_server.shared, {"m6.txt": payload})
    status, data = admin.post_json("/trash", {"path": "m6.txt"})
    assert status == 200 and data.get("success"), (status, data)
    status, data = admin.post_json(
        "/trash/restore", {"name": data["trash_name"]})
    assert status == 200 and data.get("success"), (status, data)
    target = live_server.shared / "m6.txt"
    assert target.exists()
    assert sha256_bytes(target.read_bytes()) == sha256_bytes(payload)


# M7: rename collision overwrites the destination.
def test_m7_rename_collision_refused_victim_intact(live_server):
    admin = live_server.admin_client()
    seed_files(live_server.shared, {"m7a.txt": b"A" * 32, "m7b.txt": b"B" * 32})
    status, data = admin.post_json("/rename/m7a.txt", {"name": "m7b.txt"})
    assert status == 400, (status, data)
    assert (live_server.shared / "m7b.txt").read_bytes() == b"B" * 32
    assert (live_server.shared / "m7a.txt").read_bytes() == b"A" * 32


# M8: pre-restart upload sessions treated as valid after restart.
def test_m8_stale_upload_session_invalid_after_restart(live_server):
    admin = live_server.admin_client()
    sid, _n = _init(admin, "m8.bin", 1024, chunk_size=1024)
    live_server.restart()
    admin2 = live_server.admin_client()
    status, data = admin2.post_json(f"/upload/chunk/{sid}/complete", {})
    assert status == 400, (status, data)


# M9: corrupt config silently replaced by defaults (no backup, no log).
def test_m9_corrupt_config_leaves_backup(live_server):
    import glob as _glob
    import json as _json

    import webshare_app.core.config.manager as config_manager

    cfg_file = config_manager.CONFIG_FILE
    existed = os.path.exists(cfg_file)
    before = ""
    if existed:
        with open(cfg_file, "r", encoding="utf-8") as f:
            before = f.read()
    with open(cfg_file, "w", encoding="utf-8") as f:
        _json.dump({"folder": str(live_server.shared)}, f)
    with open(cfg_file, "wb") as f:
        f.write(b"{bad json \xff\xfe")
    try:
        config_manager.ConfigManager()
        assert _glob.glob(cfg_file + ".corrupt-*"), "no corrupt backup written"
    finally:
        if existed:
            with open(cfg_file, "w", encoding="utf-8") as f:
                f.write(before)
        elif os.path.exists(cfg_file):
            os.remove(cfg_file)
        for stale in _glob.glob(cfg_file + ".corrupt-*"):
            os.remove(stale)


# M10: ZIP safety check bypassed -> member escapes root.
def test_m10_zip_slip_member_blocked(live_server, tmp_path):
    import io
    import zipfile

    admin = live_server.admin_client()
    marker = tmp_path / "m10_evil.txt"
    if marker.exists():
        marker.unlink()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../m10_evil.txt", b"ESCAPED")
    status, data = admin.post_multipart(
        "/upload/", {}, [("file", "m10.zip", buf.getvalue(), "application/zip")]
    )
    assert status == 200, data
    status, data = admin.post_json("/unzip/m10.zip", {})
    assert status == 400, (status, data)
    assert not marker.exists()
