from pathlib import Path

from config import conf


def test_csrf_enforced_for_state_changes(client, login, csrf_headers):
    token = login("admin")

    denied = client.post("/mkdir/", json={"name": "blocked"})
    assert denied.status_code == 403

    allowed = client.post(
        "/mkdir/",
        json={"name": "allowed", "csrf_token": token},
        headers=csrf_headers(token),
    )
    assert allowed.status_code == 200
    assert allowed.get_json().get("success") is True


def test_protected_system_paths_blocked_on_download_stream_preview(client, login):
    login("admin")
    base = Path(conf.get("folder"))
    protected = base / ".webshare_secret.txt"
    protected.write_text("secret", encoding="utf-8")

    for endpoint in [
        "/download/.webshare_secret.txt",
        "/stream/.webshare_secret.txt",
        "/preview/.webshare_secret.txt",
    ]:
        resp = client.get(endpoint)
        assert resp.status_code == 403


def test_health_and_ready_endpoints_public(client):
    health = client.get("/healthz")
    assert health.status_code == 200
    payload = health.get_json()
    assert payload.get("status") == "ok"
    assert "time" in payload
    assert "version" in payload

    ready = client.get("/readyz")
    assert ready.status_code in {200, 503}
    ready_payload = ready.get_json()
    assert ready_payload.get("status") in {"ready", "not_ready"}
    checks = ready_payload.get("checks", {})
    assert {"runtime_initialized", "config_loaded", "shared_folder_access"}.issubset(checks.keys())
