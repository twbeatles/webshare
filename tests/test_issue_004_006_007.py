"""Regression tests for PROJECT_AUDIT ISSUE-004, ISSUE-006, ISSUE-007.
- ISSUE-004: version restore must replace the live file atomically
  (temp copy + os.replace) and abort when the pre-restore backup fails.
- ISSUE-006: download quota reservations settle by actual delivered bytes
  on stream close; 429 messages document the fairness policy.
- ISSUE-007: login blocks and share-password blocks persist immediately
  instead of waiting for the periodic flush.
"""
import json
import os
from pathlib import Path

from config import (
    DOWNLOAD_TRACKER,
    conf,
    download_tracker_lock,
)
from security.ip_blocker import check_ip_blocked, record_login_attempt
from utils.helpers import (
    create_file_version,
    reserve_download_quota,
    settle_download_quota,
    version_name_matches_rel_path,
)
from webshare_app.services.share_service import (
    check_share_password_blocked,
    record_share_password_attempt,
)


def _restore(client, token, headers, version, target):
    return client.post(
        "/versions/restore",
        json={"version": version, "target": target, "csrf_token": token},
        headers=headers,
    )


def _only_version(base, rel):
    return next(
        p.name
        for p in (base / ".webshare_versions").iterdir()
        if version_name_matches_rel_path(p.name, rel)
    )


def test_restore_version_replaces_atomically_and_backs_up_live(client, login, csrf_headers):
    base = Path(conf.get("folder"))
    live = base / "restore_me.txt"
    live.write_text("v1-content", encoding="utf-8")
    assert create_file_version(str(live)) is True
    live.write_text("live-content", encoding="utf-8")

    token = login("admin")
    resp = _restore(client, token, csrf_headers(token), _only_version(base, "restore_me.txt"), "restore_me.txt")
    assert resp.status_code == 200
    assert resp.get_json()["success"] is True
    assert live.read_text(encoding="utf-8") == "v1-content"
    backups = [
        p
        for p in (base / ".webshare_versions").iterdir()
        if version_name_matches_rel_path(p.name, "restore_me.txt")
        and p.read_text(encoding="utf-8") == "live-content"
    ]
    assert backups, "pre-restore live content must be backed up"


def test_restore_version_aborts_when_backup_fails(client, login, csrf_headers, monkeypatch):
    base = Path(conf.get("folder"))
    (base / ".webshare_versions").mkdir(parents=True, exist_ok=True)
    live = base / "restore_abort.txt"
    live.write_text("v1-content", encoding="utf-8")
    assert create_file_version(str(live)) is True
    live.write_text("live-content", encoding="utf-8")

    token = login("admin")
    monkeypatch.setattr("routes.metadata_routes.create_file_version", lambda _path: False)
    resp = _restore(client, token, csrf_headers(token), _only_version(base, "restore_abort.txt"), "restore_abort.txt")
    assert resp.status_code == 500
    assert resp.get_json()["success"] is False
    assert live.read_text(encoding="utf-8") == "live-content"


def test_restore_version_keeps_live_intact_when_copy_fails(client, login, csrf_headers, monkeypatch):
    base = Path(conf.get("folder"))
    (base / ".webshare_versions").mkdir(parents=True, exist_ok=True)
    live = base / "restore_copyfail.txt"
    live.write_text("v1-content", encoding="utf-8")
    assert create_file_version(str(live)) is True
    live.write_text("live-content", encoding="utf-8")

    def _boom(_src, _dst):
        raise OSError("disk full")

    token = login("admin")
    monkeypatch.setattr("routes.metadata_routes.atomic_copy_file", _boom)
    resp = _restore(
        client, token, csrf_headers(token), _only_version(base, "restore_copyfail.txt"), "restore_copyfail.txt"
    )
    assert resp.status_code == 500
    assert resp.get_json()["success"] is False
    assert live.read_text(encoding="utf-8") == "live-content"


def test_settle_download_quota_refunds_undelivered_bytes(client):
    conf.set("daily_download_limit", 0)
    conf.set("daily_bandwidth_limit_mb", 0)
    ok, _, reservation = reserve_download_quota("session:settle-case", True, 1000)
    assert ok is True

    settle_download_quota(reservation, 400)
    with download_tracker_lock:
        assert DOWNLOAD_TRACKER["session:settle-case"]["bytes"] == 400
        assert DOWNLOAD_TRACKER["session:settle-case"]["count"] == 1

    # Settlement never charges extra when actual exceeds the projection.
    settle_download_quota(reservation, 5000)
    with download_tracker_lock:
        assert DOWNLOAD_TRACKER["session:settle-case"]["bytes"] == 400

    # Degenerate inputs are no-ops.
    settle_download_quota({}, 10)
    settle_download_quota(reservation, None)
    with download_tracker_lock:
        assert DOWNLOAD_TRACKER["session:settle-case"]["bytes"] == 400


def test_download_range_request_settles_quota_to_served_bytes(client, login):
    base = Path(conf.get("folder"))
    (base / "range.bin").write_bytes(b"x" * 100)

    login("admin")
    resp = client.get("/download/range.bin", headers={"Range": "bytes=0-9"})
    assert resp.status_code == 206
    resp.close()
    with download_tracker_lock:
        assert DOWNLOAD_TRACKER["session:sid-admin"]["bytes"] == 10


def test_settled_zip_response_refunds_aborted_stream(client):
    from utils.zip_utils import create_temp_zip_from_items, make_settled_zip_stream_response

    base = Path(conf.get("folder"))
    (base / "big.bin").write_bytes(os.urandom(1024 * 1024))
    temp = create_temp_zip_from_items([(str(base / "big.bin"), "big.bin")])
    zip_size = os.path.getsize(temp)

    ok, _, reservation = reserve_download_quota("session:zip-abort", True, zip_size)
    assert ok is True
    resp = make_settled_zip_stream_response(temp, "big.zip", reservation)
    stream = resp.response
    iterator = iter(stream)
    first = next(iterator)
    assert first
    closer = getattr(stream, "close", None)
    if closer is not None:
        closer()  # simulate the WSGI server aborting the transfer
    with download_tracker_lock:
        remaining = DOWNLOAD_TRACKER["session:zip-abort"]["bytes"]
    assert remaining == len(first) < zip_size


def test_quota_limit_message_documents_settlement_policy(client):
    conf.set("daily_download_limit", 1)
    ok, _, _ = reserve_download_quota("session:policy-note", True, 0)
    assert ok is True
    ok, message, _ = reserve_download_quota("session:policy-note", True, 0)
    assert ok is False
    assert "Daily download limit exceeded" in message
    assert "actual bytes" in message


def test_login_block_persists_without_periodic_flush(client):
    base = Path(conf.get("folder"))
    ip = "203.0.113.77"
    for _ in range(5):
        record_login_attempt(ip, False)
    assert check_ip_blocked(ip)[0] is True

    payload = json.loads((base / ".webshare_login_attempts.json").read_text(encoding="utf-8"))
    assert payload[ip]["attempts"] == 5
    assert payload[ip].get("blocked_until")

    audit = json.loads((base / ".webshare_audit.json").read_text(encoding="utf-8"))
    assert any(e.get("action") == "login_blocked" and e.get("target") == ip for e in audit)


def test_share_password_block_persists_without_periodic_flush(client):
    base = Path(conf.get("folder"))
    for _ in range(5):
        record_share_password_attempt("203.0.113.78", "token-y", success=False)
    assert check_share_password_blocked("203.0.113.78", "token-y")[0] is True

    payload = json.loads((base / ".webshare_share_password_attempts.json").read_text(encoding="utf-8"))
    assert payload["203.0.113.78\ntoken-y"]["attempts"] == 5

    audit = json.loads((base / ".webshare_audit.json").read_text(encoding="utf-8"))
    assert any(e.get("action") == "share_password_blocked" for e in audit)
