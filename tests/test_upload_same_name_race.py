"""Concurrent same-name uploads never overwrite each other (audit ISSUE-002)."""

import io
import threading
import time
from datetime import datetime
from pathlib import Path

from config import ACTIVE_SESSIONS, conf, session_lock
from utils.helpers import commit_no_replace


def _logged_in_client(app, name):
    client = app.test_client()
    token = f"csrf-{name}"
    sid = f"sid-{name}"
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["role"] = "admin"
        sess["session_id"] = sid
        sess["last_active"] = time.time()
        sess["_csrf_token"] = token
    with session_lock:
        ACTIVE_SESSIONS[sid] = {
            "ip": "127.0.0.1",
            "role": "admin",
            "login_time": datetime.now(),
            "last_active": datetime.now(),
        }
    return client, token


def _prepared_session(client, token, name, payload):
    headers = {"X-CSRF-Token": token}
    init = client.post(
        "/upload/chunk/init",
        json={"filename": name, "total_size": len(payload), "path": "",
              "chunk_size": len(payload), "total_chunks": 1, "csrf_token": token},
        headers=headers,
    )
    assert init.status_code == 200, init.get_json()
    sid = init.get_json()["session_id"]
    chunk = client.post(
        f"/upload/chunk/{sid}",
        data={"index": "0", "chunk": (io.BytesIO(payload), "chunk.bin")},
        content_type="multipart/form-data",
        headers=headers,
    )
    assert chunk.status_code == 200, chunk.get_json()
    return sid


def test_concurrent_same_name_chunk_completes_keep_both_files(app):
    folder = Path(conf.get("folder"))
    size = 4 << 20
    for round_index in range(4):
        for leftover in folder.glob("IMG_0001*"):
            leftover.unlink()
        ca, ta = _logged_in_client(app, f"a{round_index}")
        cb, tb = _logged_in_client(app, f"b{round_index}")
        sa = _prepared_session(ca, ta, "IMG_0001.jpg", b"A" * size)
        sb = _prepared_session(cb, tb, "IMG_0001.jpg", b"B" * size)

        results: list[tuple[int, str]] = [(0, ""), (0, "")]
        barrier = threading.Barrier(2)

        def complete(i, client, token, sid):
            barrier.wait()
            res = client.post(f"/upload/chunk/{sid}/complete", json={"csrf_token": token},
                              headers={"X-CSRF-Token": token})
            results[i] = (res.status_code, str((res.get_json() or {}).get("filename") or ""))

        threads = [
            threading.Thread(target=complete, args=(0, ca, ta, sa)),
            threading.Thread(target=complete, args=(1, cb, tb, sb)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert [r[0] for r in results] == [200, 200], results
        names = {r[1] for r in results}
        assert len(names) == 2, results
        contents = {(folder / n).read_bytes()[:1] for n in names}
        assert contents == {b"A", b"B"}


def test_commit_no_replace_picks_next_free_name(tmp_path):
    (tmp_path / "report.pdf").write_bytes(b"old")
    (tmp_path / "report_1.pdf").write_bytes(b"old1")
    temp = tmp_path / ".webshare_upload_x.tmp"
    temp.write_bytes(b"new")

    committed = commit_no_replace(str(temp), str(tmp_path / "report.pdf"))

    assert Path(committed).name == "report_2.pdf"
    assert (tmp_path / "report.pdf").read_bytes() == b"old"
    assert (tmp_path / "report_1.pdf").read_bytes() == b"old1"
    assert Path(committed).read_bytes() == b"new"
    assert not temp.exists()


def test_commit_no_replace_skips_directory_with_same_name(tmp_path):
    (tmp_path / "data").mkdir()
    temp = tmp_path / ".webshare_upload_y.tmp"
    temp.write_bytes(b"x")

    committed = commit_no_replace(str(temp), str(tmp_path / "data"))

    assert Path(committed).name == "data_1"
    assert (tmp_path / "data").is_dir()
