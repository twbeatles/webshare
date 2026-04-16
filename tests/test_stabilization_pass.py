import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from config import (
    DUPLICATE_SCAN_PROGRESS,
    SEARCH_INDEX_FILE,
    SHARE_LINKS,
    conf,
    duplicate_scan_lock,
    share_links_lock,
)
from features.cloud_sync import create_cloud_job, load_cloud_runtime_state, reset_cloud_sync_runtime_state
from features.duplicates import DUPLICATE_SCAN_JOB_KIND, cancel_duplicate_scan, scan_duplicates
from features.job_store import create_job, get_job
from features.search_indexer import SearchIndexer, indexer


def test_password_only_mode_hides_disabled_user_and_dropbox_ui(client, login):
    login("admin")

    resp = client.get("/browse/")
    assert resp.status_code == 200

    html = resp.get_data(as_text=True)
    assert "userManageModal" not in html
    assert "cloudDropboxStatus" not in html
    assert "/api/users" not in html
    assert "Dropbox integration is not implemented yet." not in html


def test_download_tracker_uses_session_for_logged_in_and_ip_for_share(client, login, monkeypatch):
    base = Path(conf.get("folder"))
    (base / "file.txt").write_text("file", encoding="utf-8")

    seen_keys = []

    def _allow(key, _count_event=True, projected_bytes=0):
        seen_keys.append(("check", key, projected_bytes))
        return True, ""

    def _track(key, size, _count_event=True):
        seen_keys.append(("track", key, size))

    monkeypatch.setattr("utils.helpers.check_download_limit", _allow)
    monkeypatch.setattr("utils.helpers.track_download", _track)

    login("admin")

    with client.session_transaction() as sess:
        sess["session_id"] = "sid-A"
    resp_a = client.get("/download/file.txt")
    assert resp_a.status_code == 200

    with client.session_transaction() as sess:
        sess["session_id"] = "sid-B"
    resp_b = client.get("/download/file.txt")
    assert resp_b.status_code == 200

    with share_links_lock:
        SHARE_LINKS["tok-file"] = {
            "path": "file.txt",
            "expires": datetime.now() + timedelta(hours=1),
            "created_by": "admin",
            "is_dir": False,
            "password_hash": None,
            "max_downloads": 0,
            "download_count": 0,
            "created_at": datetime.now().isoformat(),
        }

    share_resp = client.get("/share/tok-file")
    assert share_resp.status_code == 200

    keys = [key for _kind, key, _value in seen_keys]
    assert "session:sid-A" in keys
    assert "session:sid-B" in keys
    assert "ip:127.0.0.1" in keys


def test_cloud_job_status_is_restored_after_runtime_reset(client, login, csrf_headers):
    token = login("admin")
    headers = csrf_headers(token)

    save_resp = client.post(
        "/api/cloud/config",
        json={
            "provider": "google_drive",
            "enabled": True,
            "client_id": "client-id",
            "client_secret": "client-secret",
            "folder_id": "folder-id",
            "csrf_token": token,
        },
        headers=headers,
    )
    assert save_resp.status_code == 200

    job = create_cloud_job("google_drive", "upload", "")
    job_id = job["job_id"]

    reset_cloud_sync_runtime_state()
    load_cloud_runtime_state()

    job_resp = client.get(f"/api/cloud/jobs/{job_id}")
    assert job_resp.status_code == 200
    payload = job_resp.get_json()["job"]
    assert payload["job_id"] == job_id
    assert payload["state"] == "failed"
    assert payload["error"] == "cloud sync interrupted by restart"

    status_resp = client.get("/api/cloud/status")
    assert status_resp.status_code == 200
    google_status = status_resp.get_json()["status"]["google_drive"]
    assert google_status["job_persisted"] is True
    assert google_status["last_job"]["job_id"] == job_id


def test_search_index_snapshot_roundtrip_and_watchdog_fallback(app, monkeypatch):
    base = Path(conf.get("folder"))
    (base / "alpha.txt").write_text("alpha", encoding="utf-8")
    (base / "docs").mkdir(parents=True, exist_ok=True)
    (base / "docs" / "beta.txt").write_text("beta", encoding="utf-8")

    indexer.reset_runtime_state()
    try:
        indexer.build_index(str(base), rebuild_reason="test_build")
        assert (base / SEARCH_INDEX_FILE).exists()
        assert any(item["path"] == "docs/beta.txt" for item in indexer.search("beta"))

        build_status = indexer.get_status()
        assert build_status["snapshot_loaded"] is True
        assert build_status["last_rebuild_reason"] == "test_build"

        indexer.reset_runtime_state()
        assert indexer.load_snapshot(str(base)) is True
        snapshot_status = indexer.get_status()
        assert snapshot_status["snapshot_loaded"] is True
        assert snapshot_status["last_rebuild_reason"] == "snapshot_load"
        assert any(item["path"] == "docs/beta.txt" for item in indexer.search("beta"))

        monkeypatch.setattr(SearchIndexer, "_load_watchdog_components", staticmethod(lambda: (None, None)))
        assert indexer.start_watcher(str(base)) is False
        assert indexer.get_status()["watcher_active"] is False
    finally:
        indexer.reset_runtime_state()


def test_duplicate_scan_cancel_marks_job_cancelled(app, monkeypatch):
    base = Path(conf.get("folder"))
    for index in range(24):
        (base / f"dup-{index}.bin").write_bytes(b"x" * 2048)

    started = threading.Event()

    def _slow_hash(_filepath, chunk_size=8192):
        started.set()
        time.sleep(0.02)
        return "same-hash"

    monkeypatch.setattr("features.duplicates.calculate_file_hash", _slow_hash)

    job = create_job(
        DUPLICATE_SCAN_JOB_KIND,
        "shared_folder",
        phase="queued",
        cancelled=False,
        progress=0,
        stats={"groups": 0, "files": 0},
    )

    worker = threading.Thread(
        target=scan_duplicates,
        args=(str(base), 1024, job["job_id"]),
        daemon=True,
    )
    worker.start()

    assert started.wait(timeout=2)
    assert cancel_duplicate_scan() is True

    worker.join(timeout=5)
    assert worker.is_alive() is False

    job_state = get_job(job["job_id"])
    assert job_state is not None
    assert job_state["state"] == "cancelled"
    assert job_state["cancelled"] is True
    assert job_state["phase"] == "hashing"

    with duplicate_scan_lock:
        assert DUPLICATE_SCAN_PROGRESS["running"] is False
        assert DUPLICATE_SCAN_PROGRESS["cancelled"] is True
        assert DUPLICATE_SCAN_PROGRESS["phase"] == "hashing"
