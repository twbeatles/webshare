import io
import json
import os
import threading
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

import config as config_module
import main as main_module
import pytest
from config import DOWNLOAD_TRACKER, RECENT_FILES, SHARE_LINKS, conf, download_tracker_lock, recent_files_lock, share_links_lock
from features.transcoder import Transcoder
from utils.helpers import build_download_tracker_key, create_file_version, version_name_matches_rel_path


class _DummyTranscoder:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.playlist_path = str(Path(output_dir) / "index.m3u8")


def test_streaming_tracks_only_bytes_not_download_count(client, login, monkeypatch, tmp_path):
    base = Path(conf.get("folder"))
    media = base / "video.mkv"
    media.write_bytes(b"abcdef")

    hls_dir = tmp_path / "hls"
    hls_dir.mkdir(parents=True, exist_ok=True)
    playlist = hls_dir / "index.m3u8"
    playlist.write_text("#EXTM3U\n", encoding="utf-8")
    segment = hls_dir / "segment_000.ts"
    segment.write_bytes(b"segment")

    monkeypatch.setattr("features.transcoder.get_transcoder", lambda _path: _DummyTranscoder(str(hls_dir)))

    login("admin")
    tracker_key = build_download_tracker_key("sid-admin", "127.0.0.1")
    with download_tracker_lock:
        DOWNLOAD_TRACKER.clear()

    range_resp = client.get("/stream/video.mkv", headers={"Range": "bytes=0-1"})
    assert range_resp.status_code == 206

    playlist_resp = client.get("/stream/hls/video.mkv/index.m3u8")
    assert playlist_resp.status_code == 200

    segment_resp = client.get("/stream/hls/video.mkv/segment_000.ts")
    assert segment_resp.status_code == 200

    with download_tracker_lock:
        tracker = DOWNLOAD_TRACKER.get(tracker_key)
        assert tracker is not None
        assert tracker["count"] == 0
        assert tracker["bytes"] == 2 + playlist.stat().st_size + segment.stat().st_size

    download_resp = client.get("/download/video.mkv")
    assert download_resp.status_code == 200

    with download_tracker_lock:
        tracker = DOWNLOAD_TRACKER.get(tracker_key)
        assert tracker is not None
        assert tracker["count"] == 1
        assert tracker["bytes"] == 2 + playlist.stat().st_size + segment.stat().st_size + media.stat().st_size


def test_recent_files_populated_by_file_access(client, login):
    base = Path(conf.get("folder"))
    note = base / "note.md"
    note.write_text("# hello", encoding="utf-8")
    audio = base / "song.mp3"
    audio.write_bytes(b"12345")

    login("admin")

    assert client.get("/get_content/note.md").status_code == 200
    assert client.get("/stream/song.mp3", headers={"Range": "bytes=0-0"}).status_code == 206

    recent_resp = client.get("/recent_files")
    assert recent_resp.status_code == 200
    files = recent_resp.get_json()["files"]
    paths = [item["path"] for item in files]
    assert "note.md" in paths
    assert "song.mp3" in paths


def test_recent_files_are_isolated_by_session_and_filtered_by_permissions(client, login):
    base = Path(conf.get("folder"))
    public_file = base / "public.txt"
    public_file.write_text("public", encoding="utf-8")
    secret_dir = base / "secret"
    secret_dir.mkdir(parents=True, exist_ok=True)
    secret_file = secret_dir / "only-admin.txt"
    secret_file.write_text("secret", encoding="utf-8")

    with config_module.permissions_lock:
        config_module.FOLDER_PERMISSIONS["secret"] = {
            "read": ["admin"],
            "write": ["admin"],
            "delete": ["admin"],
        }

    login("admin")
    assert client.get("/get_content/public.txt").status_code == 200
    assert client.get("/get_content/secret/only-admin.txt").status_code == 200

    admin_recent = client.get("/recent_files").get_json()["files"]
    admin_paths = [item["path"] for item in admin_recent]
    assert "public.txt" in admin_paths
    assert "secret/only-admin.txt" in admin_paths

    guest_token = login("guest")
    assert guest_token
    guest_recent = client.get("/recent_files").get_json()["files"]
    guest_paths = [item["path"] for item in guest_recent]
    assert "public.txt" not in guest_paths
    assert "secret/only-admin.txt" not in guest_paths


def test_shared_link_access_does_not_populate_recent_files(client):
    base = Path(conf.get("folder"))
    shared_file = base / "shared.txt"
    shared_file.write_text("shared", encoding="utf-8")

    with recent_files_lock:
        RECENT_FILES.clear()
    with share_links_lock:
        SHARE_LINKS.clear()
        SHARE_LINKS["shared-token"] = {
            "path": "shared.txt",
            "expires": datetime.now() + timedelta(hours=1),
            "created_by": "admin",
            "is_dir": False,
            "password_hash": None,
            "max_downloads": 0,
            "download_count": 0,
            "created_at": datetime.now().isoformat(),
        }

    resp = client.get("/share/shared-token")
    assert resp.status_code == 200
    with recent_files_lock:
        assert RECENT_FILES == {}


def test_save_content_keeps_original_when_atomic_replace_fails(client, login, csrf_headers, monkeypatch):
    base = Path(conf.get("folder"))
    target = base / "edit.txt"
    target.write_text("original", encoding="utf-8")

    token = login("admin")
    monkeypatch.setattr("routes.media_routes.atomic_write_bytes", lambda _path, _payload: (_ for _ in ()).throw(OSError("disk full")))

    resp = client.post(
        "/save_content/edit.txt",
        json={"content": "updated", "csrf_token": token},
        headers=csrf_headers(token),
    )
    assert resp.status_code == 500
    assert target.read_text(encoding="utf-8") == "original"


def test_create_file_version_generates_unique_names_within_same_second(client):
    base = Path(conf.get("folder"))
    version_dir = base / ".webshare_versions"
    version_dir.mkdir(parents=True, exist_ok=True)
    target = base / "unique.txt"
    target.write_text("first", encoding="utf-8")

    create_file_version(str(target))
    create_file_version(str(target))

    version_names = [path.name for path in version_dir.iterdir() if version_name_matches_rel_path(path.name, "unique.txt")]
    assert len(version_names) == 2
    assert len(set(version_names)) == 2


def test_search_falls_back_to_filesystem_scan_while_indexing(client, login, monkeypatch):
    base = Path(conf.get("folder"))
    target = base / "needle.txt"
    target.write_text("find me", encoding="utf-8")

    login("admin")
    monkeypatch.setattr("routes.file_routes.indexer.search", lambda _query, _max=100: [])
    monkeypatch.setattr(
        "routes.file_routes.indexer.get_status",
        lambda: {
            "is_indexing": True,
            "pending_update": False,
            "last_indexed": None,
            "last_build_seconds": 0.0,
            "indexed_items": 0,
            "name_bucket_count": 0,
            "document_count": 0,
            "last_error": "",
        },
    )

    resp = client.get("/search?q=needle")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["indexing"] is True
    assert payload["search_mode"] == "fallback"
    assert any(item["path"] == "needle.txt" for item in payload["results"])


def test_unzip_creates_suffixed_directory_on_collision(client, login, csrf_headers):
    base = Path(conf.get("folder"))
    archive = base / "archive.zip"
    existing_dir = base / "archive"
    existing_dir.mkdir(parents=True, exist_ok=True)
    (existing_dir / "keep.txt").write_text("keep", encoding="utf-8")

    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("inside.txt", "payload")

    token = login("admin")
    resp = client.post(f"/unzip/{archive.name}", json={"csrf_token": token}, headers=csrf_headers(token))
    assert resp.status_code == 200
    assert resp.get_json()["success"] is True
    assert (existing_dir / "keep.txt").read_text(encoding="utf-8") == "keep"
    assert (base / "archive_1" / "inside.txt").read_text(encoding="utf-8") == "payload"


def test_version_listing_and_restore_support_new_and_legacy_names(client, login, csrf_headers):
    base = Path(conf.get("folder"))
    version_dir = base / ".webshare_versions"
    version_dir.mkdir(parents=True, exist_ok=True)

    dir1 = base / "dir1"
    dir2 = base / "dir2"
    dir1.mkdir(parents=True, exist_ok=True)
    dir2.mkdir(parents=True, exist_ok=True)
    file1 = dir1 / "test.txt"
    file2 = dir2 / "test.txt"

    file1.write_text("old-dir1", encoding="utf-8")
    create_file_version(str(file1))
    file2.write_text("old-dir2", encoding="utf-8")
    create_file_version(str(file2))

    legacy_version = version_dir / "20240101_010101_dir1_test.txt"
    legacy_version.write_text("legacy-dir1", encoding="utf-8")
    file1.write_text("current-dir1", encoding="utf-8")

    token = login("admin")
    list_resp = client.get("/versions/dir1/test.txt")
    assert list_resp.status_code == 200
    versions = list_resp.get_json()["versions"]
    names = [item["name"] for item in versions]
    assert names
    assert "20240101_010101_dir1_test.txt" in names
    assert all(version_name_matches_rel_path(name, "dir1/test.txt") for name in names)
    assert all(not version_name_matches_rel_path(name, "dir2/test.txt") for name in names)

    mismatched = next(name for name in version_dir.iterdir() if version_name_matches_rel_path(name.name, "dir2/test.txt"))
    bad_restore = client.post(
        "/versions/restore",
        json={"version": mismatched.name, "target": "dir1/test.txt", "csrf_token": token},
        headers=csrf_headers(token),
    )
    assert bad_restore.status_code == 200
    assert bad_restore.get_json()["success"] is False

    restore_resp = client.post(
        "/versions/restore",
        json={"version": names[0], "target": "dir1/test.txt", "csrf_token": token},
        headers=csrf_headers(token),
    )
    assert restore_resp.status_code == 200
    assert restore_resp.get_json()["success"] is True
    assert file1.read_text(encoding="utf-8") in {"old-dir1", "legacy-dir1"}
    matching_versions = [
        path
        for path in version_dir.iterdir()
        if version_name_matches_rel_path(path.name, "dir1/test.txt")
    ]
    assert any(path.read_text(encoding="utf-8") == "current-dir1" for path in matching_versions)


def test_copy_and_move_overwrite_create_versions_before_replacement(client, login, csrf_headers):
    base = Path(conf.get("folder"))
    version_dir = base / ".webshare_versions"
    token = login("admin")
    headers = csrf_headers(token)

    (base / "copy-src.txt").write_text("copy-new", encoding="utf-8")
    (base / "copy-dst.txt").write_text("copy-old", encoding="utf-8")
    copy_resp = client.post(
        "/copy",
        json={
            "source": "copy-src.txt",
            "destination": "copy-dst.txt",
            "conflict_policy": "overwrite",
            "csrf_token": token,
        },
        headers=headers,
    )
    assert copy_resp.status_code == 200
    assert copy_resp.get_json()["success"] is True
    assert (base / "copy-dst.txt").read_text(encoding="utf-8") == "copy-new"
    copy_versions = [
        path
        for path in version_dir.iterdir()
        if version_name_matches_rel_path(path.name, "copy-dst.txt")
    ]
    assert any(path.read_text(encoding="utf-8") == "copy-old" for path in copy_versions)

    (base / "move-src.txt").write_text("move-new", encoding="utf-8")
    (base / "move-dst.txt").write_text("move-old", encoding="utf-8")
    move_resp = client.post(
        "/move",
        json={
            "source": "move-src.txt",
            "destination": "move-dst.txt",
            "conflict_policy": "overwrite",
            "csrf_token": token,
        },
        headers=headers,
    )
    assert move_resp.status_code == 200
    assert move_resp.get_json()["success"] is True
    assert not (base / "move-src.txt").exists()
    assert (base / "move-dst.txt").read_text(encoding="utf-8") == "move-new"
    move_versions = [
        path
        for path in version_dir.iterdir()
        if version_name_matches_rel_path(path.name, "move-dst.txt")
    ]
    assert any(path.read_text(encoding="utf-8") == "move-old" for path in move_versions)


def test_directory_overwrite_versions_existing_files(client, login, csrf_headers):
    base = Path(conf.get("folder"))
    version_dir = base / ".webshare_versions"
    token = login("admin")
    headers = csrf_headers(token)

    src_dir = base / "dir-copy-src"
    dst_dir = base / "dir-copy-dst"
    src_dir.mkdir()
    dst_dir.mkdir()
    (src_dir / "new.txt").write_text("new", encoding="utf-8")
    (dst_dir / "old.txt").write_text("old", encoding="utf-8")

    resp = client.post(
        "/copy",
        json={
            "source": "dir-copy-src",
            "destination": "dir-copy-dst",
            "conflict_policy": "overwrite",
            "csrf_token": token,
        },
        headers=headers,
    )

    assert resp.status_code == 200
    assert resp.get_json()["success"] is True
    assert (dst_dir / "new.txt").read_text(encoding="utf-8") == "new"
    assert not (dst_dir / "old.txt").exists()
    old_versions = [
        path
        for path in version_dir.iterdir()
        if version_name_matches_rel_path(path.name, "dir-copy-dst/old.txt")
    ]
    assert any(path.read_text(encoding="utf-8") == "old" for path in old_versions)


def test_trash_and_duplicate_delete_schedule_index_refresh(client, login, csrf_headers, monkeypatch):
    base = Path(conf.get("folder"))
    file_for_trash = base / "trash-me.txt"
    file_for_trash.write_text("trash", encoding="utf-8")
    dup = base / "dup.txt"
    dup.write_text("dup", encoding="utf-8")

    token = login("admin")
    calls = []

    class _Recorder:
        def __init__(self, label):
            self.label = label

        def update_event(self, path):
            calls.append((self.label, path))

    monkeypatch.setattr("routes.trash_routes.indexer", _Recorder("trash"))
    monkeypatch.setattr("routes.duplicate_routes.indexer", _Recorder("dup"))

    trash_resp = client.post("/trash", json={"path": "trash-me.txt", "csrf_token": token}, headers=csrf_headers(token))
    assert trash_resp.status_code == 200
    assert trash_resp.get_json()["success"] is True

    trashed_name = next((base / ".webshare_trash").iterdir()).name
    restore_resp = client.post(
        "/trash/restore",
        json={"name": trashed_name, "csrf_token": token},
        headers=csrf_headers(token),
    )
    assert restore_resp.status_code == 200
    assert restore_resp.get_json()["success"] is True

    dup_resp = client.post(
        "/api/duplicates/delete",
        json={"files": ["dup.txt"], "csrf_token": token},
        headers=csrf_headers(token),
    )
    assert dup_resp.status_code == 200
    assert dup_resp.get_json()["deleted"] == 1

    kinds = [kind for kind, _ in calls]
    assert kinds.count("trash") >= 2
    assert "dup" in kinds


def test_config_manager_load_validates_values_and_creates_folder(tmp_path, monkeypatch):
    config_path = tmp_path / "webshare_config.json"
    folder = tmp_path / "created-shared"
    config_path.write_text(
        json.dumps(
            {
                "folder": str(folder),
                "port": "bad-port",
                "session_timeout": 0,
                "language": "en",
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)
    manager = config_module.ConfigManager()

    assert folder.is_dir()
    assert manager.get("folder") == str(folder.resolve())
    assert manager.get("port") == config_module.DEFAULT_PORT
    assert manager.get("session_timeout") == config_module.SESSION_TIMEOUT_MINUTES
    assert manager.get("language") == "en"


def test_config_save_uses_os_replace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    manager = config_module.ConfigManager()
    called = {"replace": False}
    original_replace = config_module.os.replace

    def _replace(src, dst):
        called["replace"] = True
        return original_replace(src, dst)

    monkeypatch.setattr(config_module.os, "replace", _replace)
    manager.save()
    assert called["replace"] is True


def test_configure_windows_dpi_safe_on_non_windows(monkeypatch):
    monkeypatch.setattr(main_module.sys, "platform", "linux")
    main_module.configure_windows_dpi()


def test_transcoder_uses_start_new_session_on_non_windows(tmp_path, monkeypatch):
    conf.set("folder", str(tmp_path))
    video = tmp_path / "video.mkv"
    video.write_bytes(b"x")
    captured = {}

    class _DummyProc:
        pid = 1234

        def poll(self):
            return None

    class _NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            return None

    def _popen(*args, **kwargs):
        captured.update(kwargs)
        return _DummyProc()

    monkeypatch.setattr("features.transcoder._is_windows", lambda: False)
    monkeypatch.setattr("features.transcoder.subprocess.Popen", _popen)
    monkeypatch.setattr("features.transcoder.threading.Thread", _NoopThread)

    transcoder = Transcoder(str(video), "session")
    transcoder.start()
    assert captured.get("start_new_session") is True


def test_transcoder_stop_terminates_child_process_group_only(tmp_path, monkeypatch):
    conf.set("folder", str(tmp_path))
    calls = []

    class _DummyProc:
        pid = 4321

        def wait(self, timeout=None):
            return None

        def poll(self):
            return None

    monkeypatch.setattr("features.transcoder._is_windows", lambda: False)
    monkeypatch.setattr("features.transcoder.os.getpgid", lambda _pid: 9876, raising=False)
    monkeypatch.setattr("features.transcoder.os.killpg", lambda pgid, sig: calls.append((pgid, sig)), raising=False)

    transcoder = Transcoder(str(tmp_path / "video.mkv"), "session-stop")
    transcoder.process = _DummyProc()
    transcoder.stop()

    assert calls
    assert calls[0][0] == 9876


def test_get_transcoder_returns_without_session_lock_deadlock(tmp_path, monkeypatch):
    from features import transcoder as transcoder_module

    conf.set("folder", str(tmp_path))
    video = tmp_path / "video.mkv"
    video.write_bytes(b"video")

    monkeypatch.setattr(Transcoder, "start", lambda self: None)
    transcoder_module.TRANSCODE_SESSIONS.clear()

    result = {"done": False}

    def _run():
        transcoder_module.get_transcoder(str(video))
        result["done"] = True

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(timeout=1)

    transcoder_module.TRANSCODE_SESSIONS.clear()
    assert result["done"] is True
    assert thread.is_alive() is False
