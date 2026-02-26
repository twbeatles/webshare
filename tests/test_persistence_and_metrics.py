from datetime import datetime, timedelta
from pathlib import Path

from config import SHARE_LINKS, STATS, audit_lock, conf, share_links_lock, stats_lock
from features.audit_log import AUDIT_LOG, flush_audit_log_if_dirty, load_audit_log, log_audit
from features.share_links_store import cleanup_expired_share_links_persisted, load_share_links, save_share_links


def test_audit_log_flush_and_reload(client):
    base = Path(conf.get("folder"))
    audit_file = base / ".webshare_audit.json"

    with audit_lock:
        AUDIT_LOG.clear()
    log_audit("admin", "test_action", "/tmp", "details", ip="127.0.0.1")
    flushed = flush_audit_log_if_dirty(force=True)
    assert flushed is True
    assert audit_file.exists()

    with audit_lock:
        AUDIT_LOG.clear()
    load_audit_log()
    with audit_lock:
        assert any(item.get("action") == "test_action" for item in AUDIT_LOG)


def test_share_links_store_roundtrip_and_expired_cleanup(client):
    now = datetime.now()
    with share_links_lock:
        SHARE_LINKS.clear()
        SHARE_LINKS["future"] = {
            "path": "a.txt",
            "expires": now + timedelta(hours=1),
            "created_by": "admin",
            "is_dir": False,
            "password_hash": None,
            "max_downloads": 0,
            "download_count": 0,
            "created_at": now.isoformat(),
        }
        SHARE_LINKS["expired"] = {
            "path": "b.txt",
            "expires": now - timedelta(minutes=1),
            "created_by": "admin",
            "is_dir": False,
            "password_hash": None,
            "max_downloads": 0,
            "download_count": 0,
            "created_at": now.isoformat(),
        }

    save_share_links()
    removed = cleanup_expired_share_links_persisted()
    assert removed >= 1

    with share_links_lock:
        SHARE_LINKS.clear()
    load_share_links()
    with share_links_lock:
        assert "future" in SHARE_LINKS
        assert "expired" not in SHARE_LINKS


def test_bytes_sent_not_double_counted_for_direct_download(client, login):
    base = Path(conf.get("folder"))
    payload = b"12345"
    (base / "size.txt").write_bytes(payload)

    with stats_lock:
        STATS["bytes_sent"] = 0
        STATS["bytes_received"] = 0
        STATS["requests"] = 0
        STATS["errors"] = 0
        STATS["active_connections"] = 0

    login("admin")
    resp = client.get("/download/size.txt")
    assert resp.status_code == 200
    assert resp.data == payload

    with stats_lock:
        assert STATS["bytes_sent"] == len(payload)

