from datetime import datetime, timedelta

from config import AUDIT_LOG, audit_lock


def test_set_language_legacy_wrapper(client):
    resp = client.get("/set_language/en")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload.get("success") is True
    assert payload.get("language") == "en"
    assert resp.headers.get("Deprecation") == "true"
    assert resp.headers.get("Sunset") == "2026-08-31"


def test_set_language_post_standard(client, login, csrf_headers):
    token = login("admin")
    resp = client.post(
        "/set_language",
        json={"lang": "ko", "csrf_token": token},
        headers=csrf_headers(token),
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body.get("success") is True
    assert body.get("language") == "ko"


def test_audit_log_limit_compatibility(client, login):
    now = datetime.now()
    with audit_lock:
        AUDIT_LOG.clear()
        for i in range(5):
            AUDIT_LOG.append(
                {
                    "timestamp": (now - timedelta(minutes=i)).isoformat(),
                    "user": "admin",
                    "ip": "127.0.0.1",
                    "action": f"act{i}",
                    "target": "/",
                    "details": "",
                    "result": "success",
                }
            )

    login("admin")
    resp = client.get("/api/audit_log?limit=2")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert isinstance(payload.get("logs"), list)
    assert len(payload["logs"]) == 2
