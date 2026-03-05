import io
import json
import os
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from flask import Response

import docker_entrypoint
import server
from config import APP_VERSION, MAX_CHUNK_UPLOAD_SIZE, SHARE_LINKS, conf, share_links_lock
from utils.file_utils import validate_path


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

    monkeypatch.setattr("utils.helpers.check_download_limit", lambda _ip: (False, "limit"))

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

    monkeypatch.setattr("utils.helpers.check_download_limit", lambda _ip: (True, ""))
    monkeypatch.setattr("utils.helpers.track_download", lambda _ip, _size: None)

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


def test_cloud_sync_endpoints_expose_mock_mode(client, login, csrf_headers):
    token = login("admin")
    headers = csrf_headers(token)

    config_resp = client.get("/api/cloud/config")
    assert config_resp.status_code == 200
    config_payload = config_resp.get_json()
    assert config_payload.get("mode") == "mock"

    status_resp = client.get("/api/cloud/status")
    assert status_resp.status_code == 200
    status_payload = status_resp.get_json()
    assert status_payload.get("mode") == "mock"
    providers = status_payload.get("status", {})
    assert "google_drive" in providers
    assert providers["google_drive"].get("mode") == "mock"

    sync_resp = client.post(
        "/api/cloud/sync/google_drive",
        json={"path": "", "direction": "upload", "csrf_token": token},
        headers=headers,
    )
    assert sync_resp.status_code == 202
    body = sync_resp.get_json()
    assert body.get("mode") == "mock"
    for key in ["job_id", "state", "progress", "error"]:
        assert key in body


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

    docker_entrypoint.main()

    assert captured.get("app") is wrapped_wsgi_app
    assert captured.get("served") is True


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



