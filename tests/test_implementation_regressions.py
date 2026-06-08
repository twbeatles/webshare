import io
import json
import os
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

import pytest
from flask import Response

import docker_entrypoint
import main
import server
from config import APP_VERSION, MAX_CHUNK_UPLOAD_SIZE, SHARE_LINKS, conf, share_links_lock
from security.auth import verify_password
from utils.file_utils import validate_path
from utils.log_manager import LogManager


def test_validate_path_rejects_symlink_escape(tmp_path):
    base = tmp_path / "base"
    outside = tmp_path / "outside"
    base.mkdir(parents=True, exist_ok=True)
    outside.mkdir(parents=True, exist_ok=True)

    link = base / "link"
    try:
        os.symlink(str(outside), str(link), target_is_directory=True)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("symlink creation is not available in this environment")

    is_valid, full_path, error = validate_path(str(base), "link/escape.txt")
    assert is_valid is False
    assert full_path == ""
    assert error


def test_chunk_upload_rejects_total_size_over_limit(client, login, csrf_headers):
    token = login("admin")
    resp = client.post(
        "/upload/chunk/init",
        json={
            "filename": "oversize.bin",
            "total_size": MAX_CHUNK_UPLOAD_SIZE + 1,
            "path": "",
            "csrf_token": token,
        },
        headers=csrf_headers(token),
    )

    assert resp.status_code == 400
    payload = resp.get_json()
    assert "total_size" in payload.get("error", "")


def test_chunk_upload_rejects_owner_mismatch_for_all_mutations(client, login, csrf_headers):
    token = login("admin")
    headers = csrf_headers(token)

    init = client.post(
        "/upload/chunk/init",
        json={
            "filename": "owner-check.txt",
            "total_size": 3,
            "path": "",
            "chunk_size": 3,
            "total_chunks": 1,
            "csrf_token": token,
        },
        headers=headers,
    )
    assert init.status_code == 200
    sid = init.get_json()["session_id"]

    # Simulate a different owner context by mutating session_id.
    with client.session_transaction() as sess:
        sess["session_id"] = "sid-different-owner"

    chunk_resp = client.post(
        f"/upload/chunk/{sid}",
        data={"index": "0", "chunk": (io.BytesIO(b"abc"), "chunk.bin")},
        content_type="multipart/form-data",
        headers=headers,
    )
    assert chunk_resp.status_code == 403

    complete_resp = client.post(
        f"/upload/chunk/{sid}/complete",
        json={"csrf_token": token},
        headers=headers,
    )
    assert complete_resp.status_code == 403

    cancel_resp = client.post(
        f"/upload/chunk/{sid}/cancel",
        json={"csrf_token": token},
        headers=headers,
    )
    assert cancel_resp.status_code == 403


def test_chunk_upload_rejects_when_disk_preflight_has_insufficient_space(client, login, csrf_headers, monkeypatch):
    token = login("admin")
    monkeypatch.setattr(
        "webshare_app.services.upload_service.shutil.disk_usage",
        lambda _path: SimpleNamespace(total=2048, used=1024, free=1024),
    )

    resp = client.post(
        "/upload/chunk/init",
        json={
            "filename": "disk-full.bin",
            "total_size": 1,
            "path": "",
            "chunk_size": 1,
            "total_chunks": 1,
            "csrf_token": token,
        },
        headers=csrf_headers(token),
    )

    assert resp.status_code == 507
    assert "디스크" in resp.get_json().get("error", "")


def test_chunk_upload_post_commit_index_failure_keeps_committed_file(client, login, csrf_headers, monkeypatch):
    token = login("admin")
    headers = csrf_headers(token)
    base = Path(conf.get("folder"))

    init = client.post(
        "/upload/chunk/init",
        json={
            "filename": "committed.txt",
            "total_size": 3,
            "path": "",
            "chunk_size": 3,
            "total_chunks": 1,
            "csrf_token": token,
        },
        headers=headers,
    )
    assert init.status_code == 200
    sid = init.get_json()["session_id"]

    chunk_resp = client.post(
        f"/upload/chunk/{sid}",
        data={"index": "0", "chunk": (io.BytesIO(b"abc"), "chunk.bin")},
        content_type="multipart/form-data",
        headers=headers,
    )
    assert chunk_resp.status_code == 200

    monkeypatch.setattr(
        "routes.upload_routes.indexer.update_event",
        lambda _path: (_ for _ in ()).throw(RuntimeError("index failed")),
    )
    complete_resp = client.post(
        f"/upload/chunk/{sid}/complete",
        json={"csrf_token": token},
        headers=headers,
    )

    assert complete_resp.status_code == 200
    assert complete_resp.get_json()["success"] is True
    assert (base / "committed.txt").read_text(encoding="utf-8") == "abc"


def test_special_character_browse_paths_are_encoded_in_redirect_and_breadcrumb(client, login):
    base = Path(conf.get("folder"))
    folder_name = "folder #% &"
    file_name = "file #% &.txt"
    folder = base / folder_name
    child = folder / "child"
    child.mkdir(parents=True, exist_ok=True)
    special_file = base / file_name
    special_file.write_text("special", encoding="utf-8")

    login("admin")

    redirect_resp = client.get("/browse/" + quote(file_name, safe="/"))
    assert redirect_resp.status_code == 302
    assert redirect_resp.headers["Location"].endswith("/download/" + quote(file_name, safe="/"))

    browse_resp = client.get("/browse/" + quote(f"{folder_name}/child", safe="/"))
    assert browse_resp.status_code == 200
    html = browse_resp.get_data(as_text=True)
    assert f'href="/browse/{quote(folder_name, safe="")}"' in html



def test_folder_upload_collision_keeps_nested_parent_path(client, login, csrf_headers):
    base = Path(conf.get("folder"))
    nested = base / "nested"
    nested.mkdir(parents=True, exist_ok=True)
    (nested / "keep.txt").write_text("old", encoding="utf-8")

    token = login("admin")
    resp = client.post(
        "/upload/",
        data={
            "paths": "nested/keep.txt",
            "file": (io.BytesIO(b"new"), "keep.txt"),
        },
        content_type="multipart/form-data",
        headers=csrf_headers(token),
    )
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload.get("success") is True

    assert (nested / "keep_1.txt").exists()
    assert (base / "keep_1.txt").exists() is False


def test_batch_download_limit_checked_before_zip_creation(client, login, csrf_headers, monkeypatch):
    base = Path(conf.get("folder"))
    folder = base / "batch"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "a.txt").write_text("a", encoding="utf-8")

    token = login("admin")
    called = {"zip_called": False}

    monkeypatch.setattr("utils.helpers.check_download_limit", lambda _ip, _count_event=True, projected_bytes=0: (False, "limit"))

    def _fail_if_called(_items):
        called["zip_called"] = True
        raise AssertionError("zip creation should not run when pre-check fails")

    monkeypatch.setattr("routes.file_routes.create_temp_zip_from_items", _fail_if_called)

    resp = client.post(
        "/batch_download/batch",
        data={"files": json.dumps(["a.txt"])},
        headers=csrf_headers(token),
    )
    assert resp.status_code == 429
    assert called["zip_called"] is False


def test_clipboard_isolation_by_session_id(client, login, csrf_headers):
    token = login("admin")
    headers = csrf_headers(token)

    with client.session_transaction() as sess:
        sess["session_id"] = "sid-A"
    resp_a_set = client.post("/clipboard", json={"content": "alpha"}, headers=headers)
    assert resp_a_set.status_code == 200

    with client.session_transaction() as sess:
        sess["session_id"] = "sid-B"
    resp_b_set = client.post("/clipboard", json={"content": "beta"}, headers=headers)
    assert resp_b_set.status_code == 200

    with client.session_transaction() as sess:
        sess["session_id"] = "sid-A"
    resp_a_get = client.get("/clipboard")
    assert resp_a_get.status_code == 200
    assert resp_a_get.get_json().get("content") == "alpha"

    with client.session_transaction() as sess:
        sess["session_id"] = "sid-B"
    resp_b_get = client.get("/clipboard")
    assert resp_b_get.status_code == 200
    assert resp_b_get.get_json().get("content") == "beta"

def test_share_max_downloads_atomic_reservation(app, monkeypatch):
    base = Path(conf.get("folder"))
    (base / "race.txt").write_text("race", encoding="utf-8")

    with share_links_lock:
        SHARE_LINKS.clear()
        SHARE_LINKS["tok-race"] = {
            "path": "race.txt",
            "expires": datetime.now() + timedelta(hours=1),
            "created_by": "admin",
            "is_dir": False,
            "password_hash": None,
            "max_downloads": 1,
            "download_count": 0,
            "created_at": datetime.now().isoformat(),
        }

    monkeypatch.setattr("utils.helpers.check_download_limit", lambda _ip, _count_event=True, projected_bytes=0: (True, ""))
    monkeypatch.setattr("utils.helpers.track_download", lambda _ip, _size, _count_event=True: None)

    def _fake_send_from_directory(_folder, _path):
        # Keep request alive briefly so concurrent request can race reserve check.
        time.sleep(0.05)
        return Response(b"ok", mimetype="application/octet-stream")

    monkeypatch.setattr("routes.share_routes.send_from_directory", _fake_send_from_directory)

    start = threading.Event()
    results = []

    def _worker():
        with app.test_client() as local_client:
            start.wait(timeout=2)
            resp = local_client.get("/share/tok-race")
            results.append((resp.status_code, resp.mimetype))

    threads = [threading.Thread(target=_worker) for _ in range(2)]
    for thread in threads:
        thread.start()

    start.set()
    for thread in threads:
        thread.join(timeout=2)

    assert len(results) == 2
    success_count = sum(mime == "application/octet-stream" for _, mime in results)
    assert success_count == 1

    with share_links_lock:
        assert SHARE_LINKS["tok-race"]["download_count"] == 1


def test_share_max_downloads_exceeded_returns_429(client):
    base = Path(conf.get("folder"))
    (base / "already.txt").write_text("shared", encoding="utf-8")

    with share_links_lock:
        SHARE_LINKS.clear()
        SHARE_LINKS["tok-limit"] = {
            "path": "already.txt",
            "expires": datetime.now() + timedelta(hours=1),
            "created_by": "admin",
            "is_dir": False,
            "password_hash": None,
            "max_downloads": 1,
            "download_count": 1,
            "created_at": datetime.now().isoformat(),
        }

    resp = client.get("/share/tok-limit")
    assert resp.status_code == 429


def test_cloud_sync_endpoints_expose_google_drive_and_dropbox_placeholder(client, login, csrf_headers, monkeypatch):
    token = login("admin")
    headers = csrf_headers(token)

    config_resp = client.get("/api/cloud/config")
    assert config_resp.status_code == 200
    config_payload = config_resp.get_json()
    config = config_payload.get("config", {})
    assert config["google_drive"]["implementation"] == "google_drive"
    assert config["google_drive"]["supported"] is True
    assert config["google_drive"]["visible"] is True
    assert config["google_drive"]["conflict_policy"] == "skip"
    assert config["google_drive"]["job_persisted"] is True
    assert config["dropbox"]["implementation"] == "placeholder"
    assert config["dropbox"]["supported"] is False
    assert config["dropbox"]["visible"] is False

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
    assert save_resp.get_json()["success"] is True

    status_resp = client.get("/api/cloud/status")
    assert status_resp.status_code == 200
    status_payload = status_resp.get_json()
    providers = status_payload.get("status", {})
    assert providers["google_drive"]["implementation"] == "google_drive"
    assert providers["google_drive"]["supported"] is True
    assert providers["google_drive"]["conflict_policy"] == "skip"
    assert providers["google_drive"]["job_persisted"] is True
    assert providers["dropbox"]["implementation"] == "placeholder"
    assert providers["dropbox"]["state"] == "not_implemented"

    monkeypatch.setattr(
        "routes.cloud_routes.start_google_drive_job",
        lambda direction, abs_path, rel_path: {
            "job_id": "google-job-1",
            "provider": "google_drive",
            "path": rel_path,
            "direction": direction,
            "state": "accepted",
            "progress": 0,
            "error": None,
        },
    )

    sync_resp = client.post(
        "/api/cloud/sync/google_drive",
        json={"path": "", "direction": "upload", "csrf_token": token},
        headers=headers,
    )
    assert sync_resp.status_code == 202
    body = sync_resp.get_json()
    assert body.get("success") is True
    assert body["job"]["job_id"] == "google-job-1"
    assert body["job"]["state"] == "accepted"

    dropbox_resp = client.post(
        "/api/cloud/sync/dropbox",
        json={"path": "", "direction": "upload", "csrf_token": token},
        headers=headers,
    )
    assert dropbox_resp.status_code == 501
    assert dropbox_resp.get_json()["implementation"] == "placeholder"


def test_google_drive_auth_start_callback_disconnect_and_job_status(client, login, csrf_headers, monkeypatch):
    token = login("admin")
    headers = csrf_headers(token)

    client.post(
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

    monkeypatch.setattr(
        "routes.cloud_routes.GoogleDriveClient.build_auth_url",
        lambda self, redirect_uri, state: f"https://example.test/oauth?state={state}&redirect_uri={redirect_uri}",
    )
    monkeypatch.setattr(
        "routes.cloud_routes.GoogleDriveClient.exchange_code",
        lambda self, code, redirect_uri: {"access_token": "token", "refresh_token": "refresh", "expires_in": 3600},
    )
    monkeypatch.setattr(
        "routes.cloud_routes.get_cloud_job",
        lambda job_id: {"job_id": job_id, "state": "completed", "progress": 100},
    )

    start_resp = client.get("/api/cloud/google_drive/auth/start")
    assert start_resp.status_code == 302
    assert "https://example.test/oauth" in start_resp.headers["Location"]

    with client.session_transaction() as sess:
        state = sess["cloud_google_drive_oauth_state"]

    callback_resp = client.get(f"/api/cloud/google_drive/auth/callback?code=ok&state={state}")
    assert callback_resp.status_code == 200
    assert b"Google Drive connected successfully." in callback_resp.data

    job_resp = client.get("/api/cloud/jobs/google-job-xyz")
    assert job_resp.status_code == 200
    assert job_resp.get_json()["job"]["job_id"] == "google-job-xyz"

    disconnect_resp = client.post(
        "/api/cloud/google_drive/disconnect",
        json={"csrf_token": token},
        headers=headers,
    )
    assert disconnect_resp.status_code == 200
    assert disconnect_resp.get_json()["success"] is True


def test_google_drive_oauth_callback_escapes_error_message(client, login):
    login("admin")
    payload = quote("</script><script>alert(1)</script>", safe="")

    resp = client.get(f"/api/cloud/google_drive/auth/callback?error={payload}")
    body = resp.get_data(as_text=True)

    assert resp.status_code == 200
    assert "</script><script>alert(1)</script>" not in body
    assert "&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "\\u003c/script\\u003e\\u003cscript\\u003ealert(1)\\u003c/script\\u003e" in body


def test_upnp_endpoints_report_status_map_and_unmap(client, login, csrf_headers, monkeypatch):
    token = login("admin")
    headers = csrf_headers(token)

    monkeypatch.setattr(
        "routes.network_routes.get_upnp_status",
        lambda port: {"port": port, "protocol": "TCP", "mapped": False, "external_ip": "", "internal_ip": "", "error": ""},
    )
    monkeypatch.setattr(
        "routes.network_routes.map_upnp_port",
        lambda port: {"port": port, "protocol": "TCP", "mapped": True, "external_ip": "203.0.113.2", "internal_ip": "192.168.0.2", "error": ""},
    )
    monkeypatch.setattr(
        "routes.network_routes.unmap_upnp_port",
        lambda port: {"port": port, "protocol": "TCP", "mapped": False, "external_ip": "203.0.113.2", "internal_ip": "192.168.0.2", "error": ""},
    )

    status_resp = client.get("/api/network/upnp/status")
    assert status_resp.status_code == 200
    assert status_resp.get_json()["upnp"]["mapped"] is False

    map_resp = client.post("/api/network/upnp/map", json={"csrf_token": token}, headers=headers)
    assert map_resp.status_code == 200
    assert map_resp.get_json()["upnp"]["mapped"] is True

    unmap_resp = client.post("/api/network/upnp/unmap", json={"csrf_token": token}, headers=headers)
    assert unmap_resp.status_code == 200
    assert unmap_resp.get_json()["upnp"]["mapped"] is False


def test_server_thread_passes_composed_wsgi_to_make_server(monkeypatch):
    wrapped_wsgi_app = object()
    captured = {}

    class _DummyServer:
        socket = None

        def serve_forever(self):
            return None

        def shutdown(self):
            return None

        def server_close(self):
            return None

    monkeypatch.setattr(server, "build_composed_wsgi_app", lambda: (object(), wrapped_wsgi_app))

    def _fake_make_server(host, port, app, threaded=True, ssl_context=None):
        captured["host"] = host
        captured["port"] = port
        captured["app"] = app
        return _DummyServer()

    monkeypatch.setattr(server, "make_server", _fake_make_server)
    monkeypatch.setattr(server, "ensure_runtime_initialized", lambda: None)
    monkeypatch.setattr(server, "start_periodic_cleanup", lambda: None)
    monkeypatch.setattr("features.search_indexer.indexer.build_index", lambda _root: None)

    thread = server.ServerThread(use_https=False)
    thread.run()

    assert captured.get("app") is wrapped_wsgi_app
    assert thread.ready_event.is_set() is False


def test_start_server_wait_ready_reports_bind_failure(monkeypatch):
    monkeypatch.setattr(server, "server_thread", None)

    def _boom(*args, **kwargs):
        err = OSError("already in use")
        err.errno = 10048
        raise err

    monkeypatch.setattr(server, "make_server", _boom)
    monkeypatch.setattr(server, "build_composed_wsgi_app", lambda: (object(), object()))

    started = server.start_server(wait_ready=True, timeout=0.5)
    assert started is False
    assert "포트" in server.get_server_startup_error()


def test_docker_entrypoint_uses_composed_wsgi_path(monkeypatch):
    wrapped_wsgi_app = object()
    captured = {"served": False}

    class _DummyServer:
        def serve_forever(self):
            captured["served"] = True
            return None

        def server_close(self):
            return None

    class _NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            return None

    monkeypatch.setattr(docker_entrypoint, "cleanup_upload_temp_dirs", lambda _folder: 0)
    monkeypatch.setattr(docker_entrypoint, "ensure_runtime_initialized", lambda: None)
    monkeypatch.setattr(docker_entrypoint, "start_periodic_cleanup", lambda: None)
    monkeypatch.setattr(docker_entrypoint.atexit, "register", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(docker_entrypoint, "build_composed_wsgi_app", lambda: (object(), wrapped_wsgi_app))
    monkeypatch.setattr(docker_entrypoint.threading, "Thread", _NoopThread)

    def _fake_make_server(host, port, app, threaded=True):
        captured["host"] = host
        captured["port"] = port
        captured["app"] = app
        captured["threaded"] = threaded
        return _DummyServer()

    monkeypatch.setattr(docker_entrypoint, "make_server", _fake_make_server)

    base = conf.get("folder")
    monkeypatch.setenv("WEBSHARE_FOLDER", base)
    monkeypatch.setenv("WEBSHARE_HOST", "127.0.0.1")
    monkeypatch.setenv("WEBSHARE_PORT", "5010")
    monkeypatch.setenv("WEBSHARE_ADMIN_PASSWORD", "admin-secret")
    monkeypatch.setenv("WEBSHARE_GUEST_PASSWORD", "guest-secret")
    monkeypatch.setenv("WEBSHARE_SECRET_KEY", "docker-secret")

    docker_entrypoint.main()

    assert captured.get("app") is wrapped_wsgi_app
    assert captured.get("served") is True
    assert verify_password(conf.get("admin_pw"), "admin-secret")
    assert verify_password(conf.get("guest_pw"), "guest-secret")
    assert conf.get("secret_key") == "docker-secret"


def test_logger_tolerates_windowed_pyinstaller_without_console(monkeypatch):
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "__stdout__", None)

    log_manager = LogManager()
    log_manager.add("windowed startup")

    assert "windowed startup" in log_manager.queue.get_nowait()


def test_main_smoke_check_runs_without_console(monkeypatch, tmp_path):
    original_folder = conf.get("folder")
    original_display_host = conf.get("display_host")
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "__stdout__", None)
    monkeypatch.setenv("WEBSHARE_SMOKE_DIR", str(tmp_path / "smoke"))

    result = main.run_smoke_check()

    assert result == 0
    assert conf.get("folder") == original_folder
    assert conf.get("display_host") == original_display_host


def test_version_strings_are_synced_with_app_version():
    root = Path(__file__).resolve().parents[1]
    readme_ko = (root / "README.md").read_text(encoding="utf-8")
    readme_en = (root / "README_EN.md").read_text(encoding="utf-8")
    gui_code = (root / "gui" / "pyqt_gui.py").read_text(encoding="utf-8")

    assert f"# WebShare Pro v{APP_VERSION}" in readme_ko
    assert f"# WebShare Pro v{APP_VERSION}" in readme_en
    assert f"version-{APP_VERSION}-blue" in readme_ko
    assert f"version-{APP_VERSION}-blue" in readme_en
    assert f"WebSharePro_v{APP_VERSION}.exe" in readme_ko
    assert 'QLabel(f"v{APP_VERSION}")' in gui_code


def test_pyinstaller_specs_keep_runtime_hiddenimports_synced():
    root = Path(__file__).resolve().parents[1]
    webshare_pro_spec = (root / "WebSharePro.spec").read_text(encoding="utf-8")
    webshare_spec = (root / "webshare.spec").read_text(encoding="utf-8")

    for spec in (webshare_pro_spec, webshare_spec):
        assert 'collect_submodules("webshare_app")' in spec
        assert '"utils.api_errors"' in spec
        assert '"utils.app_paths"' in spec
        assert '"features.share_links_store"' in spec
        assert '"features.network"' in spec
        assert '"features.webdav_server"' in spec
        assert '"routes.upload_routes"' in spec
        assert '("static", "static")' in spec
        assert '("templates", "templates")' in spec
        assert 'name=f"WebSharePro_v{APP_VERSION}"' in spec



