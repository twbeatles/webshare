import io
import json
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from config import SHARE_LINKS, conf, share_links_lock
from features.share_links_store import load_share_links, save_share_links
from routes.share_routes import (
    _share_password_attempts,
    _share_password_attempts_lock,
    flush_share_password_attempts_if_dirty,
    load_share_password_attempts,
)
from webshare_app.core.app_paths import ensure_config_secret_key, get_or_create_secret_key, secret_key_file_path
from webshare_app.core.config import ConfigManager
from webshare_app.services.file_service import resolve_folder_upload_target


def test_share_links_persist_concurrent_saves(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    conf.set("folder", str(shared))

    with share_links_lock:
        SHARE_LINKS.clear()
        SHARE_LINKS["tok-a"] = {
            "path": "a.txt",
            "expires": datetime.now() + timedelta(hours=1),
            "created_by": "admin",
            "is_dir": False,
            "password_hash": None,
            "max_downloads": 2,
            "download_count": 1,
            "created_at": datetime.now().isoformat(),
        }
        SHARE_LINKS["tok-b"] = {
            "path": "b.txt",
            "expires": datetime.now() + timedelta(hours=1),
            "created_by": "admin",
            "is_dir": False,
            "password_hash": None,
            "max_downloads": 2,
            "download_count": 2,
            "created_at": datetime.now().isoformat(),
        }

    errors = []

    def _writer(token: str, count: int):
        try:
            with share_links_lock:
                SHARE_LINKS[token]["download_count"] = count
            save_share_links()
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=_writer, args=("tok-a", 5)),
        threading.Thread(target=_writer, args=("tok-b", 7)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert not errors
    load_share_links()
    with share_links_lock:
        assert SHARE_LINKS["tok-a"]["download_count"] == 5
        assert SHARE_LINKS["tok-b"]["download_count"] == 7


def test_complete_chunk_upload_idempotent(client, login, csrf_headers):
    token = login("admin")
    headers = csrf_headers(token)

    init = client.post(
        "/upload/chunk/init",
        json={
            "filename": "idem.txt",
            "total_size": 6,
            "path": "",
            "chunk_size": 3,
            "total_chunks": 2,
            "csrf_token": token,
        },
        headers=headers,
    )
    sid = init.get_json()["session_id"]

    for index, payload in enumerate([b"abc", b"def"]):
        resp = client.post(
            f"/upload/chunk/{sid}",
            data={"index": str(index), "chunk": (io.BytesIO(payload), "chunk.bin")},
            content_type="multipart/form-data",
            headers=headers,
        )
        assert resp.status_code == 200

    first = client.post(
        f"/upload/chunk/{sid}/complete",
        json={"csrf_token": token},
        headers=headers,
    )
    assert first.status_code == 200
    assert first.get_json()["success"] is True

    second = client.post(
        f"/upload/chunk/{sid}/complete",
        json={"csrf_token": token},
        headers=headers,
    )
    assert second.status_code == 200
    body = second.get_json()
    assert body["success"] is True
    assert body.get("idempotent") is True
    assert list(Path(conf.get("folder")).glob("idem*.txt"))


def test_folder_upload_path_traversal_variants(client, login, csrf_headers):
    token = login("admin")
    headers = csrf_headers(token)
    base = Path(conf.get("folder"))

    blocked = client.post(
        "/upload/",
        data={
            "file": (io.BytesIO(b"x"), "evil.txt"),
            "paths": "../outside.txt",
        },
        content_type="multipart/form-data",
        headers=headers,
    )
    assert blocked.status_code == 200
    files = blocked.get_json()["files"]
    assert files[0]["success"] is False
    assert (base / "outside.txt").exists() is False

    ok = client.post(
        "/upload/",
        data={
            "file": (io.BytesIO(b"ok"), "nested.txt"),
            "paths": "subdir/nested.txt",
        },
        content_type="multipart/form-data",
        headers=headers,
    )
    assert ok.status_code == 200
    assert ok.get_json()["files"][0]["success"] is True
    assert (base / "subdir" / "nested.txt").read_text(encoding="utf-8") == "ok"


def test_resolve_folder_upload_target_rejects_parent_segments():
    base = str(Path(conf.get("folder")))
    ok, _, _, error = resolve_folder_upload_target(base, "", "..\\secret.txt", "file.txt")
    assert ok is False
    assert error


def test_clipboard_content_size_limit(client, login, csrf_headers):
    token = login("admin")
    headers = csrf_headers(token)
    huge = "x" * (256 * 1024 + 1)

    resp = client.post("/clipboard", json={"content": huge}, headers=headers)
    assert resp.status_code == 413


def test_secret_key_persisted_across_restart(tmp_path, monkeypatch):
    config_dir = tmp_path / "app_config"
    config_dir.mkdir()
    monkeypatch.setenv("WEBSHARE_CONFIG_DIR", str(config_dir))

    first = get_or_create_secret_key()
    second = get_or_create_secret_key()
    assert first == second
    assert Path(secret_key_file_path()).exists()


def test_config_manager_ensure_secret_key_persists(tmp_path, monkeypatch):
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    monkeypatch.setenv("WEBSHARE_CONFIG_DIR", str(config_dir))

    manager = ConfigManager()
    manager.config["secret_key"] = None
    key = ensure_config_secret_key(manager)
    assert key
    assert manager.get("secret_key") == key


def test_share_password_attempts_persist_after_flush(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    shared.mkdir()
    conf.set("folder", str(shared))

    with _share_password_attempts_lock:
        _share_password_attempts.clear()
        _share_password_attempts[("1.2.3.4", "tok")] = {"attempts": 2}

    assert flush_share_password_attempts_if_dirty(force=True) is True
    load_share_password_attempts()
    with _share_password_attempts_lock:
        assert _share_password_attempts[("1.2.3.4", "tok")]["attempts"] == 2

    from features.runtime_state import load_share_password_attempts as load_attempts_from_disk

    loaded = load_attempts_from_disk()
    assert loaded[("1.2.3.4", "tok")]["attempts"] == 2


def test_security_status_api(client, login):
    token = login("admin")
    resp = client.get("/api/security/status")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert "warnings" in payload
    assert payload.get("single_process_only") is True


def test_capabilities_and_dropbox_placeholder(client, login, csrf_headers):
    token = login("admin")
    headers = csrf_headers(token)

    caps = client.get("/api/capabilities")
    assert caps.status_code == 200
    body = caps.get_json()
    assert "hls" in body
    assert "webdav" in body

    dropbox = client.post(
        "/api/cloud/sync/dropbox",
        json={"path": "", "direction": "upload", "csrf_token": token},
        headers=headers,
    )
    assert dropbox.status_code == 501