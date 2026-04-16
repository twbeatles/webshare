from datetime import datetime, timedelta
from pathlib import Path

from config import AUDIT_LOG, audit_lock, conf


def _assert_error_schema(payload):
    assert isinstance(payload, dict)
    assert payload.get("success") is False
    assert isinstance(payload.get("error"), str) and payload.get("error")
    assert isinstance(payload.get("code"), str) and payload.get("code")
    assert isinstance(payload.get("message"), str) and payload.get("message")
    assert isinstance(payload.get("request_id"), str) and payload.get("request_id")


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


def test_active_sessions_requires_admin(client, login):
    login("guest")
    resp = client.get("/api/active_sessions")
    assert resp.status_code == 403
    _assert_error_schema(resp.get_json())


def test_users_api_exposes_login_linkage_notice(client, login):
    login("admin")
    resp = client.get("/api/users")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload.get("enabled") is False
    assert payload.get("login_mode") == "password_only"
    assert payload.get("login_linked") is False
    assert isinstance(payload.get("reason"), str) and payload.get("reason")
    assert isinstance(payload.get("notice"), str) and payload.get("notice")


def test_users_api_mutations_are_disabled(client, login, csrf_headers):
    token = login("admin")
    headers = csrf_headers(token)

    resp = client.post(
        "/api/users",
        json={"username": "new-user", "password": "pw", "csrf_token": token},
        headers=headers,
    )
    assert resp.status_code == 409
    payload = resp.get_json()
    _assert_error_schema(payload)
    assert payload.get("code") == "USER_API_DISABLED"


def test_share_create_rejects_invalid_hours_type(client, login, csrf_headers):
    base = Path(conf.get("folder"))
    (base / "a.txt").write_text("x", encoding="utf-8")

    token = login("admin")
    resp = client.post(
        "/share/create",
        json={"path": "a.txt", "hours": "bad", "csrf_token": token},
        headers=csrf_headers(token),
    )
    assert resp.status_code == 400
    body = resp.get_json()
    assert body.get("success") is False
    assert "hours" in body.get("error", "")


def test_error_schema_applies_to_download_not_found(client, login):
    login("admin")
    resp = client.get("/download/no_such_file.txt")
    assert resp.status_code == 404
    _assert_error_schema(resp.get_json())


def test_error_schema_applies_to_api_not_found_resource(client, login):
    login("admin")
    resp = client.get("/api/users/no_such_user")
    assert resp.status_code == 409
    _assert_error_schema(resp.get_json())
