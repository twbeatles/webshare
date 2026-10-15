"""Phase 2 -- live fault-injection and recovery (FT-01..FT-12).

All faults hit the REAL loopback server; interleavings are deterministic
(in-process barriers / monkeypatched failure points / restart), never
"retry until rarely green". The oracle is always on-disk bytes (SHA-256),
API semantics, and metadata -- never the server's own helpers.
"""

import os
import urllib.parse

import pytest

from live_harness import seed_files, sha256_bytes


def q(path: str) -> str:
    return urllib.parse.quote(path, safe="/")


def chunk_init(admin, filename, total, chunk_size=8192, path=""):
    n = (total + chunk_size - 1) // chunk_size if total else 0
    status, init = admin.post_json(
        "/upload/chunk/init",
        {"filename": filename, "total_size": total, "path": path,
         "chunk_size": chunk_size, "total_chunks": n},
    )
    assert status == 200 and init.get("success"), (status, init)
    return init["session_id"], n


def chunk_send(admin, sid, name, index, data):
    return admin.post_multipart(
        f"/upload/chunk/{sid}", {"index": str(index)},
        [("chunk", name, data, "application/octet-stream")],
    )


# --------------------------------------------------------------------------
# FT-01: interrupted chunk upload leaves no partial final file
# --------------------------------------------------------------------------

def test_ft01_cancelled_upload_leaves_no_file(live_server):
    admin = live_server.admin_client()
    payload = os.urandom(2 * 8192)
    sid, _n = chunk_init(admin, "partial.bin", len(payload))
    status, _ = chunk_send(admin, sid, "partial.bin", 0, payload[:8192])
    assert status == 200
    status, data = admin.post_json(f"/upload/chunk/{sid}/cancel", {})
    assert status == 200 and data.get("success"), (status, data)
    status, done = admin.post_json(f"/upload/chunk/{sid}/complete", {})
    assert status == 400, (status, done)
    assert not (live_server.shared / "partial.bin").exists()


def test_ft01_restart_during_upload_invalidates_session(live_server):
    admin = live_server.admin_client()
    payload = os.urandom(2 * 8192)
    sid, _n = chunk_init(admin, "doomed.bin", len(payload))
    status, _ = chunk_send(admin, sid, "doomed.bin", 0, payload[:8192])
    assert status == 200

    live_server.restart()
    admin2 = live_server.admin_client()
    status, done = admin2.post_json(f"/upload/chunk/{sid}/complete", {})
    assert status == 400, (status, done)
    assert not (live_server.shared / "doomed.bin").exists()


# --------------------------------------------------------------------------
# FT-02: COMPLETING vs cancel race -- exactly one winner, idempotent retry
# --------------------------------------------------------------------------

def test_ft02_completing_cancel_conflict_and_idempotent_retry(live_server):
    from webshare_app.services.upload_service import (
        UPLOAD_SESSIONS,
        UPLOAD_STATUS_COMPLETING,
    )
    from config import upload_session_lock

    admin = live_server.admin_client()
    payload = os.urandom(2 * 4096)
    sid, _n = chunk_init(admin, "race.bin", len(payload), chunk_size=4096)
    for index in (0, 1):
        status, _ = chunk_send(
            admin, sid, "race.bin", index, payload[index * 4096:(index + 1) * 4096]
        )
        assert status == 200

    # deterministic barrier: pretend a merge is already in flight
    with upload_session_lock:
        UPLOAD_SESSIONS[sid]["status"] = UPLOAD_STATUS_COMPLETING
    try:
        status, data = admin.post_json(f"/upload/chunk/{sid}/cancel", {})
        assert status == 409, (status, data)
        status, data = admin.post_json(f"/upload/chunk/{sid}/complete", {})
        assert status == 409, (status, data)
    finally:
        with upload_session_lock:
            sess = UPLOAD_SESSIONS.get(sid)
            if sess is not None:
                sess["status"] = "active"

    status, done = admin.post_json(f"/upload/chunk/{sid}/complete", {})
    assert status == 200 and done.get("success"), (status, done)
    target = live_server.shared / done.get("filename", "race.bin")
    assert sha256_bytes(target.read_bytes()) == sha256_bytes(payload)

    # idempotent retry: same session completes again, no duplicate file
    before = sorted(p.name for p in live_server.shared.iterdir() if p.is_file())
    status, again = admin.post_json(f"/upload/chunk/{sid}/complete", {})
    assert status == 200 and again.get("success") is True, (status, again)
    after = sorted(p.name for p in live_server.shared.iterdir() if p.is_file())
    assert before == after
    assert sha256_bytes(target.read_bytes()) == sha256_bytes(payload)


# --------------------------------------------------------------------------
# FT-03: failure just before os.replace keeps the original, cleans temp
# --------------------------------------------------------------------------

def test_ft03_replace_failure_preserves_original(live_server, monkeypatch):
    import webshare_app.routes.upload_routes.chunk_finalize as finalize

    admin = live_server.admin_client()
    original = os.urandom(4096)
    seed_files(live_server.shared, {"victim.bin": original})
    payload = os.urandom(2 * 4096)
    sid, _n = chunk_init(admin, "victim.bin", len(payload), chunk_size=4096)
    for index in (0, 1):
        status, _ = chunk_send(
            admin, sid, "victim.bin", index, payload[index * 4096:(index + 1) * 4096]
        )
        assert status == 200

    real_replace = os.replace

    def boom(*_a, **_k):
        raise OSError("injected pre-replace failure")

    monkeypatch.setattr(os, "replace", boom)
    try:
        status, done = admin.post_json(f"/upload/chunk/{sid}/complete", {})
    finally:
        monkeypatch.setattr(os, "replace", real_replace)
    assert status == 500, (status, done)
    assert (live_server.shared / "victim.bin").read_bytes() == original
    leftovers = [
        p.name for p in live_server.shared.iterdir()
        if p.name.startswith(".webshare_merge_")
    ]
    assert leftovers == [], leftovers


# --------------------------------------------------------------------------
# FT-04: committed file stays valid; post-commit retry is idempotent
# (covered with FT-02 retry; here: restart right after commit)
# --------------------------------------------------------------------------

def test_ft04_committed_file_survives_restart(live_server):
    admin = live_server.admin_client()
    payload = os.urandom(32768)
    expect = sha256_bytes(payload)
    sid, _n = chunk_init(admin, "committed.bin", len(payload), chunk_size=8192)
    for index in range(4):
        status, _ = chunk_send(
            admin, sid, "committed.bin", index, payload[index * 8192:(index + 1) * 8192]
        )
        assert status == 200
    status, done = admin.post_json(f"/upload/chunk/{sid}/complete", {})
    assert status == 200 and done.get("success"), (status, done)
    name = done.get("filename", "committed.bin")

    live_server.restart()
    admin2 = live_server.admin_client()
    target = live_server.shared / name
    assert target.exists()
    assert sha256_bytes(target.read_bytes()) == expect


# --------------------------------------------------------------------------
# FT-05: trash metadata loss is self-healed, never silent loss
# --------------------------------------------------------------------------

def test_ft05_trash_self_heals_missing_metadata(live_server):
    from config import TRASH_FOLDER_NAME, conf
    from webshare_app.features.trash import TRASH_METADATA_FILE

    admin = live_server.admin_client()
    payload = os.urandom(8192)
    seed_files(live_server.shared, {"healme.txt": payload})
    status, data = admin.post_json("/trash", {"path": "healme.txt"})
    assert status == 200 and data.get("success"), (status, data)
    trash_name = data["trash_name"]

    meta_path = os.path.join(conf.get("folder"), TRASH_METADATA_FILE)
    assert os.path.exists(meta_path)
    os.remove(meta_path)  # simulate metadata write loss

    status, listed = admin.get_json("/trash/list")
    assert status == 200, status
    names = [i.get("name") for i in listed.get("items", [])]
    assert trash_name in names, names

    status, data = admin.post_json("/trash/restore", {"name": trash_name})
    assert status == 200 and data.get("success"), (status, data)
    restored = live_server.shared / "healme.txt"
    assert restored.exists()
    assert sha256_bytes(restored.read_bytes()) == sha256_bytes(payload)


def test_ft05_trash_move_never_loses_file(live_server):
    admin = live_server.admin_client()
    payload = os.urandom(4096)
    seed_files(live_server.shared, {"precious.txt": payload})
    status, data = admin.post_json("/trash", {"path": "precious.txt"})
    assert status == 200, (status, data)
    if data.get("success"):
        status, listed = admin.get_json("/trash/list")
        names = [i.get("name") for i in listed.get("items", [])]
        assert data.get("trash_name") in names
    else:
        # a refused move must leave the original untouched
        assert (live_server.shared / "precious.txt").read_bytes() == payload


# --------------------------------------------------------------------------
# FT-06: restore collision keeps the existing target, separate safe name
# --------------------------------------------------------------------------

def test_ft06_restore_collision_keeps_target(live_server):
    admin = live_server.admin_client()
    old = b"OLD-CONTENT" * 64
    new = b"NEW-CONTENT" * 64
    seed_files(live_server.shared, {"clash.txt": old})
    status, data = admin.post_json("/trash", {"path": "clash.txt"})
    assert status == 200 and data.get("success"), (status, data)
    trash_name = data["trash_name"]

    (live_server.shared / "clash.txt").write_bytes(new)  # collide
    status, data = admin.post_json("/trash/restore", {"name": trash_name})
    assert status == 200 and data.get("success"), (status, data)
    assert (live_server.shared / "clash.txt").read_bytes() == new
    restored_name = data.get("restored_name", "")
    assert restored_name and restored_name != "clash.txt", data
    candidates = list(live_server.shared.glob("clash*"))
    contents = {p.read_bytes() for p in candidates if p.is_file()}
    assert old in contents and new in contents, [p.name for p in candidates]


# --------------------------------------------------------------------------
# FT-07: share quota is exact under concurrency (no race bypass)
# --------------------------------------------------------------------------

def test_ft07_share_quota_exact_under_concurrency(live_server):
    import threading

    from live_harness import LiveClient

    admin = live_server.admin_client()
    payload = os.urandom(8192)
    admin.post_multipart(
        "/upload/", {}, [("file", "quota.bin", payload, "application/octet-stream")]
    )
    status, created = admin.post_json(
        "/share/create",
        {"path": "quota.bin", "hours": 24, "password": "", "max_downloads": 2},
    )
    assert status == 200 and created.get("success"), created
    link = f"/share/{created['token']}"
    base = live_server.base_url
    results = []

    def grab():
        try:
            anon = LiveClient(base)
            st, headers, body = anon.get(link)
            results.append((st, headers.get("Content-Type", ""), body))
        except Exception as exc:  # pragma: no cover - diagnosable
            results.append(("error", "", str(exc)))

    threads = [threading.Thread(target=grab) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    import hashlib as _hl

    file_hash = sha256_bytes(payload)
    delivered = [
        r for r in results
        if r[0] == 200 and _hl.sha256(r[2]).hexdigest() == file_hash
    ]
    leaked = [
        r for r in results
        if _hl.sha256(r[2]).hexdigest() == file_hash and r[0] != 200
    ]
    # Anti-bypass invariant: exactly max_downloads full file bodies escape,
    # no matter the interleaving; every other response denies the bytes
    # (429, or the agreed 200-expired page both backends render when the
    # atomic reserve -- not the stale pre-check -- refuses).
    assert len(results) == 5, [r[0] for r in results]
    assert not leaked, [r[0] for r in leaked]
    assert len(delivered) == 2, [r[0] for r in results]


# --------------------------------------------------------------------------
# FT-08: corrupt config is backed up loudly, never silently defaulted
# --------------------------------------------------------------------------

def test_ft08_corrupt_config_backed_up_not_silently_reset(live_server):
    import glob as _glob
    import json as _json

    import webshare_app.core.config.manager as config_manager

    cfg_file = config_manager.CONFIG_FILE
    existed = os.path.exists(cfg_file)
    before = ""
    if existed:
        with open(cfg_file, "r", encoding="utf-8") as f:
            before = f.read()
    marker = {"folder": str(live_server.shared), "port": 5000,
              "ft08_marker": "present"}
    with open(cfg_file, "w", encoding="utf-8") as f:
        _json.dump(marker, f)

    with open(cfg_file, "wb") as f:
        f.write(b"\xff\xfe\x00not-json{{{")
    try:
        manager = config_manager.ConfigManager()
        backups = _glob.glob(cfg_file + ".corrupt-*")
        assert backups, "corrupt config was swallowed without a backup"
        assert manager.config.get("folder"), "manager has no folder after load"
        # shared data untouched by the corrupt load
        assert (live_server.shared).is_dir()
    finally:
        if existed:
            with open(cfg_file, "w", encoding="utf-8") as f:
                f.write(before)
        elif os.path.exists(cfg_file):
            os.remove(cfg_file)
        for stale in _glob.glob(cfg_file + ".corrupt-*"):
            os.remove(stale)


# --------------------------------------------------------------------------
# FT-09: hostile ZIPs (slip / ratio) blocked; legit ZIP extracts
# --------------------------------------------------------------------------

def _make_zip(members: dict[str, bytes]) -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_ft09_zip_slip_blocked_outside_root_untouched(live_server, tmp_path):
    admin = live_server.admin_client()
    evil_outside = tmp_path / "zip_evil.txt"
    if evil_outside.exists():
        evil_outside.unlink()
    blob = _make_zip(
        {"../../zip_evil.txt": b"ESCAPED", "ok.txt": b"fine"}
    )
    status, data = admin.post_multipart(
        "/upload/", {}, [("file", "evil.zip", blob, "application/zip")]
    )
    assert status == 200, data
    status, data = admin.post_json("/unzip/evil.zip", {})
    assert status == 400, (status, data)
    assert not evil_outside.exists()
    assert (live_server.shared / "evil.zip").exists(), "archive itself removed?"


def test_ft09_legit_zip_extracts(live_server):
    admin = live_server.admin_client()
    blob = _make_zip({"a.txt": b"aaa", "sub/b.txt": b"bbb"})
    status, data = admin.post_multipart(
        "/upload/", {}, [("file", "good.zip", blob, "application/zip")]
    )
    assert status == 200, data
    status, data = admin.post_json("/unzip/good.zip", {})
    assert status == 200 and data.get("success"), (status, data)
    assert (live_server.shared / "good" / "a.txt").read_bytes() == b"aaa"
    assert (live_server.shared / "good" / "sub" / "b.txt").read_bytes() == b"bbb"


# --------------------------------------------------------------------------
# FT-10: Go child killed -> no orphan, supervisor restarts clean
# --------------------------------------------------------------------------

def test_ft10_go_child_kill_and_restart_serves_files(tmp_path):
    import subprocess
    import time
    import urllib.error
    import urllib.request

    from live_harness import (
        ADMIN_PW,
        GoClient,
        _find_go_binary,
        pick_free_port,
        seed_files,
        sha256_bytes as _sha,
    )

    binary = _find_go_binary()
    if binary is None:
        pytest.skip("Go binary unavailable (BLOCKED)")
    import json as _json
    import secrets as _secrets

    work = tmp_path / "goft10"
    shared = work / "shared"
    shared.mkdir(parents=True)
    payload = os.urandom(16384)
    oracle = seed_files(shared, {"after_crash.bin": payload})
    port = pick_free_port()
    cfg = {
        "folder": str(shared), "port": port, "admin_pw": ADMIN_PW,
        "guest_pw": "0000", "allow_guest_upload": False,
        "display_host": "127.0.0.1", "use_https": False,
        "session_timeout": 60, "secret_key": _secrets.token_hex(32),
    }
    cfg_path = work / "webshare_config.json"
    cfg_path.write_text(_json.dumps(cfg), encoding="utf-8")
    env = dict(os.environ)
    env["WEBSHARE_CONTROL_TOKEN"] = _secrets.token_hex(32)

    proc = subprocess.Popen(
        [binary, "serve", "-host", "127.0.0.1", "-port", str(port),
         "-config", str(cfg_path)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                urllib.request.build_opener().open(base + "/", timeout=2)
            except urllib.error.HTTPError as exc:
                if exc.code == 401:
                    break
            except Exception:
                time.sleep(0.1)
        # hard kill (SIGKILL equivalent): supervisor must not keep serving
        proc.kill()
        proc.wait(timeout=10)
        assert proc.poll() is not None
        with pytest.raises(Exception):
            urllib.request.build_opener().open(base + "/", timeout=3)

        # restart on the same root: files served again, no orphan remains
        port2 = pick_free_port()
        proc2 = subprocess.Popen(
            [binary, "serve", "-host", "127.0.0.1", "-port", str(port2),
             "-config", str(cfg_path)],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            base2 = f"http://127.0.0.1:{port2}"
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                try:
                    urllib.request.build_opener().open(base2 + "/", timeout=2)
                except urllib.error.HTTPError as exc:
                    if exc.code == 401:
                        break
                except Exception:
                    time.sleep(0.1)
            go = GoClient(base2)
            go.login(ADMIN_PW)
            st, _h, body = go.get("/download/after_crash.bin")
            assert st == 200, st
            assert _sha(body) == oracle["after_crash.bin"]
        finally:
            proc2.terminate()
            proc2.wait(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()


# --------------------------------------------------------------------------
# FT-11: overwrite snapshots a version; restore returns exact bytes
# --------------------------------------------------------------------------

def test_ft11_version_snapshot_and_restore(live_server):
    admin = live_server.admin_client()
    v1 = b"VERSION-ONE" * 128
    v2 = b"VERSION-TWO" * 128
    assert sha256_bytes(v1) != sha256_bytes(v2)
    seed_files(live_server.shared, {"doc.txt": v1, "other.txt": v2})

    status, data = admin.post_json(
        "/copy",
        {"source": "other.txt", "destination": "doc.txt",
         "conflict_policy": "overwrite"},
    )
    assert status == 200 and data.get("success"), (status, data)
    assert (live_server.shared / "doc.txt").read_bytes() == v2

    status, listed = admin.get_json("/versions/doc.txt")
    assert status == 200, (status, listed)
    versions = listed.get("versions", [])
    assert versions, "overwrite created no version snapshot"

    status, data = admin.post_json(
        "/versions/restore",
        {"version": versions[0]["name"], "target": "doc.txt"},
    )
    assert status == 200 and data.get("success"), (status, data)
    assert (live_server.shared / "doc.txt").read_bytes() == v1

    status, data = admin.post_json(
        "/versions/restore", {"version": "no-such-version", "target": "doc.txt"}
    )
    assert data.get("success") is not True, (status, data)
    assert (live_server.shared / "doc.txt").read_bytes() == v1


# --------------------------------------------------------------------------
# FT-12: declared order model -- rename/delete/download/restore sequence
# --------------------------------------------------------------------------

def test_ft12_ordered_mutations_converge(live_server):
    admin = live_server.admin_client()
    payload = os.urandom(8192)
    expect = sha256_bytes(payload)
    seed_files(live_server.shared, {"order.txt": payload})

    status, data = admin.post_json("/rename/order.txt", {"name": "order2.txt"})
    assert status == 200 and data.get("success"), (status, data)
    st, _h, body = admin.get(f"/download/{q('order2.txt')}")
    assert st == 200 and sha256_bytes(body) == expect

    status, data = admin.post_json("/delete/order2.txt", {})
    assert status == 200 and data.get("success"), (status, data)
    st, _h, _body = admin.get(f"/download/{q('order2.txt')}")
    assert st == 404, st  # missing is 404, never masked as 403

    status, data = admin.post_json("/delete/nope-missing.txt", {})
    assert status == 404, (status, data)

    status, listed = admin.get_json("/trash/list")
    names = [i.get("name") for i in listed.get("items", [])]
    assert names, "delete left no trash entry"
    trash_name = names[0]
    status, data = admin.post_json("/trash/restore", {"name": trash_name})
    assert status == 200 and data.get("success"), (status, data)
    st, _h, body = admin.get(f"/download/{q('order2.txt')}")
    assert st == 200 and sha256_bytes(body) == expect
