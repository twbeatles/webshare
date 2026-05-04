import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path

from config import (
    DOWNLOAD_TRACKER,
    FOLDER_PERMISSIONS,
    LOGIN_ATTEMPTS,
    SHARE_LINKS,
    conf,
    download_tracker_lock,
    login_attempts_lock,
    permissions_lock,
    share_links_lock,
)
from features.cloud_sync import GoogleDriveClient, get_cloud_secrets_path, load_cloud_config, update_cloud_provider
from features.runtime_state import (
    flush_runtime_state_if_dirty,
    load_download_tracker,
    load_login_attempts,
)
from routes.share_routes import (
    _share_password_attempts,
    _share_password_attempts_lock,
    check_share_password_blocked,
    flush_share_password_attempts_if_dirty,
    load_share_password_attempts,
    record_share_password_attempt,
)
from security.auth import is_password_hash, verify_password
from security.ip_blocker import record_login_attempt
from security.permissions import load_permissions
from utils.helpers import reserve_download_quota
from utils.request_policy import is_protected_system_path


def test_plaintext_admin_password_migrates_to_pbkdf2_on_login(client):
    conf.config["admin_pw"] = "plain-secret"

    resp = client.post("/", data={"password": "plain-secret"})

    assert resp.status_code == 302
    stored = conf.get("admin_pw")
    assert stored != "plain-secret"
    assert is_password_hash(stored)
    assert verify_password(stored, "plain-secret")


def test_legacy_sha256_password_migrates_after_successful_login(client):
    conf.config["guest_pw"] = hashlib.sha256(b"legacy-secret").hexdigest()

    resp = client.post("/", data={"password": "legacy-secret"})

    assert resp.status_code == 302
    stored = conf.get("guest_pw")
    assert is_password_hash(stored)
    assert verify_password(stored, "legacy-secret")


def test_config_password_set_hashes_new_values(client):
    conf.set("guest_pw", "new-guest-secret")
    stored = conf.get("guest_pw")
    assert stored != "new-guest-secret"
    assert is_password_hash(stored)
    assert verify_password(stored, "new-guest-secret")


def test_cloud_config_keeps_secrets_out_of_shared_folder(client, login, csrf_headers):
    base = Path(conf.get("folder"))
    token = login("admin")

    resp = client.post(
        "/api/cloud/config",
        json={
            "provider": "google_drive",
            "enabled": True,
            "client_id": "client-id",
            "client_secret": "client-secret",
            "folder_id": "folder-id",
            "csrf_token": token,
        },
        headers=csrf_headers(token),
    )

    assert resp.status_code == 200
    shared_payload = json.loads((base / ".webshare_cloud.json").read_text(encoding="utf-8"))
    assert "client_secret" not in shared_payload["google_drive"]
    assert "token" not in shared_payload["google_drive"]

    secret_payload = json.loads(Path(get_cloud_secrets_path()).read_text(encoding="utf-8"))
    assert secret_payload["google_drive"]["client_secret"] == "client-secret"
    assert resp.get_json()["config"]["client_secret_configured"] is True


def test_cloud_tokens_are_saved_only_to_external_secret_store(client):
    update_cloud_provider("google_drive", {"token": {"access_token": "a", "refresh_token": "r"}})

    base = Path(conf.get("folder"))
    shared_payload = json.loads((base / ".webshare_cloud.json").read_text(encoding="utf-8"))
    secret_payload = json.loads(Path(get_cloud_secrets_path()).read_text(encoding="utf-8"))

    assert "token" not in shared_payload["google_drive"]
    assert secret_payload["google_drive"]["token"]["refresh_token"] == "r"

    from config import CLOUD_SYNC_CONFIG, cloud_sync_lock

    with cloud_sync_lock:
        CLOUD_SYNC_CONFIG["google_drive"]["token"] = None
    load_cloud_config()
    with cloud_sync_lock:
        token_bundle = CLOUD_SYNC_CONFIG["google_drive"]["token"]
        assert isinstance(token_bundle, dict)
        assert token_bundle["refresh_token"] == "r"


def test_google_drive_remote_segments_are_sanitized_and_resolved_inside_share(client):
    base = Path(conf.get("folder"))
    client_obj = GoogleDriveClient(conflict_policy="rename")
    remote_names = ["../x", ".webshare_cloud.json", "a/b.txt", "CON", ""]

    for remote_name in remote_names:
        segment = client_obj._safe_remote_segment(remote_name)
        ok, local_path, error = client_obj._resolve_download_target(str(base), segment)
        rel = Path(local_path).relative_to(base).as_posix() if local_path else ""
        assert ok, error
        assert ".." not in rel.split("/")
        assert not is_protected_system_path(rel)


def test_permission_api_rejects_invalid_schema_and_loader_skips_bad_entries(client, login, csrf_headers):
    base = Path(conf.get("folder"))
    (base / "ok").mkdir()
    (base / "bad").mkdir()
    token = login("admin")

    resp = client.post(
        "/api/permissions",
        json={"path": "ok", "read": ["nobody"], "write": ["admin"], "delete": ["admin"], "csrf_token": token},
        headers=csrf_headers(token),
    )
    assert resp.status_code == 400

    (base / ".webshare_permissions.json").write_text(
        json.dumps(
            {
                "ok": {"read": ["guest"], "write": ["admin"], "delete": ["admin"]},
                ".webshare_secret": {"read": ["*"]},
                "bad": {"read": ["nobody"]},
            }
        ),
        encoding="utf-8",
    )
    load_permissions()
    with permissions_lock:
        assert set(FOLDER_PERMISSIONS) == {"ok"}
        assert FOLDER_PERMISSIONS["ok"]["read"] == ["guest"]


def test_quota_login_and_share_attempt_state_survives_reload(client):
    ok, _, _ = reserve_download_quota("session:persisted", True, 12)
    assert ok is True
    record_login_attempt("203.0.113.10", success=False)
    for _ in range(5):
        record_share_password_attempt("203.0.113.11", "token-x", success=False)

    flush_runtime_state_if_dirty(force=True)
    flush_share_password_attempts_if_dirty(force=True)

    with download_tracker_lock:
        DOWNLOAD_TRACKER.clear()
    with login_attempts_lock:
        LOGIN_ATTEMPTS.clear()
    with _share_password_attempts_lock:
        _share_password_attempts.clear()

    load_download_tracker()
    load_login_attempts()
    load_share_password_attempts()

    with download_tracker_lock:
        assert DOWNLOAD_TRACKER["session:persisted"]["bytes"] == 12
    with login_attempts_lock:
        assert LOGIN_ATTEMPTS["203.0.113.10"]["attempts"] == 1
    assert check_share_password_blocked("203.0.113.11", "token-x")[0] is True


def test_service_worker_does_not_install_cache_authenticated_html(client, login):
    sw = client.get("/sw.js")
    body = sw.get_data(as_text=True)
    assert "const OFFLINE_URL = '/offline.html';" in body
    assert "const OFFLINE_URL = '/';" not in body
    assert "caches.match(event.request)" not in body.split("else if (event.request.mode === 'navigate')", 1)[1].split("else if", 1)[0]

    token = login("admin")
    assert token
    html_resp = client.get("/browse/")
    assert html_resp.headers["Cache-Control"] == "no-store"
    api_resp = client.get("/api/capabilities")
    assert api_resp.headers["Cache-Control"] == "no-store"


def test_share_link_single_file_is_attachment_by_default_and_inline_opt_in(client):
    base = Path(conf.get("folder"))
    (base / "shared.txt").write_text("shared", encoding="utf-8")
    with share_links_lock:
        SHARE_LINKS["tok-file"] = {
            "path": "shared.txt",
            "expires": datetime.now() + timedelta(hours=1),
            "created_by": "admin",
            "is_dir": False,
            "password_hash": None,
            "max_downloads": 0,
            "download_count": 0,
            "created_at": datetime.now().isoformat(),
        }

    attachment = client.get("/share/tok-file")
    assert attachment.status_code == 200
    assert "attachment" in attachment.headers.get("Content-Disposition", "")

    inline = client.get("/share/tok-file?inline=1")
    assert inline.status_code == 200
    assert "inline" in inline.headers.get("Content-Disposition", "")


def test_metadata_limits_and_svg_thumbnail_headers(client, login, csrf_headers):
    base = Path(conf.get("folder"))
    (base / "note.txt").write_text("note", encoding="utf-8")
    (base / "icon.svg").write_text("<svg><script>alert(1)</script></svg>", encoding="utf-8")
    token = login("admin")

    bad_color = client.post(
        "/api/tags",
        json={"path": "note.txt", "tag": "tag", "color": "red", "csrf_token": token},
        headers=csrf_headers(token),
    )
    assert bad_color.status_code == 400

    long_memo = client.post(
        "/api/memo/note.txt",
        json={"memo": "x" * 10001, "csrf_token": token},
        headers=csrf_headers(token),
    )
    assert long_memo.status_code == 400

    svg = client.get("/thumbnail/icon.svg")
    assert svg.status_code == 200
    assert "sandbox" in svg.headers.get("Content-Security-Policy", "")
    assert svg.headers.get("X-Content-Type-Options") == "nosniff"


def test_capabilities_endpoint_shape(client, login):
    login("admin")
    resp = client.get("/api/capabilities")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert {"hls", "webdav", "upnp", "doc_preview", "system_stats"}.issubset(payload)
    assert {"docx", "xlsx", "pptx"}.issubset(payload["doc_preview"])
