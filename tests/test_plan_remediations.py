import shutil
from pathlib import Path

import pytest

from config import FOLDER_PERMISSIONS, conf, permissions_lock
from features.cloud_sync import GoogleDriveClient, create_cloud_job
from features.job_store import get_job
from utils.helpers import reserve_download_quota, rollback_download_quota


def test_copy_move_conflict_policy_renames_by_default(client, login):
    base = Path(conf.get("folder"))
    (base / "source.txt").write_text("source", encoding="utf-8")
    (base / "target.txt").write_text("target", encoding="utf-8")
    (base / "target_1.txt").write_text("target-1", encoding="utf-8")

    token = login("admin")
    resp = client.post(
        "/copy",
        json={"source": "source.txt", "destination": "target.txt", "csrf_token": token},
    )
    assert resp.status_code == 200
    assert resp.get_json()["path"] == "target_2.txt"
    assert (base / "target.txt").read_text(encoding="utf-8") == "target"
    assert (base / "target_1.txt").read_text(encoding="utf-8") == "target-1"
    assert (base / "target_2.txt").read_text(encoding="utf-8") == "source"

    fail_resp = client.post(
        "/move",
        json={
            "source": "source.txt",
            "destination": "target.txt",
            "conflict_policy": "fail",
            "csrf_token": token,
        },
    )
    assert fail_resp.status_code == 409
    assert (base / "source.txt").exists()


def test_move_conflict_policy_overwrite_replaces_target(client, login):
    base = Path(conf.get("folder"))
    (base / "source.txt").write_text("source", encoding="utf-8")
    (base / "target.txt").write_text("target", encoding="utf-8")

    token = login("admin")
    resp = client.post(
        "/move",
        json={
            "source": "source.txt",
            "destination": "target.txt",
            "conflict_policy": "overwrite",
            "csrf_token": token,
        },
    )

    assert resp.status_code == 200
    assert resp.get_json()["path"] == "target.txt"
    assert not (base / "source.txt").exists()
    assert (base / "target.txt").read_text(encoding="utf-8") == "source"


def test_trash_restore_uses_original_path_and_recreates_parent(client, login):
    base = Path(conf.get("folder"))
    nested = base / "a" / "b"
    nested.mkdir(parents=True)
    target = nested / "report.txt"
    target.write_text("report", encoding="utf-8")

    token = login("admin")
    delete_resp = client.post("/trash", json={"path": "a/b/report.txt", "csrf_token": token})
    assert delete_resp.status_code == 200
    trash_name = delete_resp.get_json()["trash_name"]
    shutil.rmtree(base / "a")

    restore_resp = client.post("/trash/restore", json={"name": trash_name, "csrf_token": token})
    assert restore_resp.status_code == 200
    assert (base / "a" / "b" / "report.txt").read_text(encoding="utf-8") == "report"


def test_trash_restore_legacy_timestamp_name(client, login):
    base = Path(conf.get("folder"))
    trash_dir = base / ".webshare_trash"
    trash_dir.mkdir(parents=True, exist_ok=True)
    legacy = trash_dir / "20240101_010101_old.txt"
    legacy.write_text("legacy", encoding="utf-8")

    token = login("admin")
    restore_resp = client.post("/trash/restore", json={"name": legacy.name, "csrf_token": token})

    assert restore_resp.status_code == 200
    assert (base / "old.txt").read_text(encoding="utf-8") == "legacy"


def test_empty_permission_list_is_explicit_deny(client, login):
    base = Path(conf.get("folder"))
    (base / "blocked").mkdir()
    (base / "blocked" / "note.txt").write_text("secret", encoding="utf-8")
    with permissions_lock:
        FOLDER_PERMISSIONS["blocked"] = {"read": []}

    login("guest")
    resp = client.get("/browse/blocked")
    assert resp.status_code == 403


def test_config_rejects_string_bool_and_negative_quota():
    with pytest.raises(ValueError):
        conf.set("allow_guest_upload", "false")
    with pytest.raises(ValueError):
        conf.set("daily_download_limit", -1)


def test_download_quota_reserve_and_rollback():
    conf.set("daily_download_limit", 1)
    ok, message, reservation = reserve_download_quota("session:test", True, 10)
    assert ok is True
    assert message == ""

    ok, message, _ = reserve_download_quota("session:test", True, 1)
    assert ok is False
    assert "Daily download limit exceeded" in message

    rollback_download_quota(reservation)
    ok, message, _ = reserve_download_quota("session:test", True, 1)
    assert ok is True
    assert message == ""


def test_cloud_job_cancel_endpoint_marks_cancel_requested(client, login):
    token = login("admin")
    job = create_cloud_job("google_drive", "upload", "", conflict_policy="rename")

    resp = client.post(f"/api/cloud/jobs/{job['job_id']}/cancel", json={"csrf_token": token})
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["job"]["cancel_requested"] is True
    stored_job = get_job(job["job_id"])
    assert stored_job is not None
    assert stored_job["cancel_requested"] is True


def test_cloud_dry_run_upload_reports_stats_without_transfer(tmp_path):
    local_file = tmp_path / "upload.txt"
    local_file.write_text("payload", encoding="utf-8")
    progress_calls = []

    client = GoogleDriveClient(conflict_policy="dry_run")
    stats = client.sync_upload(str(local_file), "drive-folder", lambda done, total: progress_calls.append((done, total)))

    assert stats["files"] == 1
    assert stats["dry_run"] == 1
    assert stats["uploaded"] == 0
    assert progress_calls == [(1, 1)]
