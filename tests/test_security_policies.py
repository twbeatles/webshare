from pathlib import Path

from config import conf
from routes.media_routes import MAX_TEXT_EDIT_SIZE


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


def test_get_content_rejects_file_over_10mb(client, login):
    login("admin")
    base = Path(conf.get("folder"))
    big = base / "too_big_get.txt"
    big.write_bytes(b"a" * (MAX_TEXT_EDIT_SIZE + 1))

    resp = client.get("/get_content/too_big_get.txt")
    assert resp.status_code == 413
    payload = resp.get_json()
    assert payload.get("max_bytes") == MAX_TEXT_EDIT_SIZE
    assert payload.get("file_size") == MAX_TEXT_EDIT_SIZE + 1


def test_save_content_rejects_payload_over_10mb(client, login, csrf_headers):
    token = login("admin")
    base = Path(conf.get("folder"))
    target = base / "too_big_save.txt"
    target.write_text("seed", encoding="utf-8")

    content = "a" * (MAX_TEXT_EDIT_SIZE + 1)
    resp = client.post(
        "/save_content/too_big_save.txt",
        json={"content": content, "csrf_token": token},
        headers=csrf_headers(token),
    )
    assert resp.status_code == 413
    payload = resp.get_json()
    assert payload.get("max_bytes") == MAX_TEXT_EDIT_SIZE
    assert payload.get("content_size") == MAX_TEXT_EDIT_SIZE + 1


def test_json_document_preview_escapes_html_payload(client, login):
    login("admin")
    base = Path(conf.get("folder"))
    sample = base / "xss.json"
    sample.write_text('{"k":"<img src=x onerror=alert(1)>"}', encoding="utf-8")

    resp = client.get("/preview/xss.json")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload.get("success") is True
    assert payload.get("type") == "html"
    content = payload.get("content", "")
    assert "&lt;img src=x onerror=alert(1)&gt;" in content
    assert "<img src=x onerror=alert(1)>" not in content
