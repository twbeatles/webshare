"""PROJECT_AUDIT.md Phase 1 회귀 테스트 (ISSUE-001/002/005)."""

import io
import shutil
import zipfile
from pathlib import Path
from types import SimpleNamespace

from config import conf, upload_session_lock
from routes.upload_routes import UPLOAD_SESSIONS
from webshare_app.services.upload_service import (
    UPLOAD_STATUS_COMPLETING,
    _cleanup_upload_session,
)


def _init_chunk_session(client, token, headers, filename, total_size, chunk_size, total_chunks):
    init = client.post(
        "/upload/chunk/init",
        json={
            "filename": filename,
            "total_size": total_size,
            "path": "",
            "chunk_size": chunk_size,
            "total_chunks": total_chunks,
            "csrf_token": token,
        },
        headers=headers,
    )
    assert init.status_code == 200
    return init.get_json()["session_id"]


def _upload_chunk(client, sid, index, payload, headers):
    resp = client.post(
        f"/upload/chunk/{sid}",
        data={"index": str(index), "chunk": (io.BytesIO(payload), "chunk.bin")},
        content_type="multipart/form-data",
        headers=headers,
    )
    assert resp.status_code == 200


# ISSUE-002: 손상된 설정 파일이 시작을 죽이지 않아야 함
def test_config_load_corrupt_utf8_boots_with_defaults_and_backs_up(tmp_path, monkeypatch):
    import webshare_app.core.config.manager as manager_module
    from webshare_app.core.config import ConfigManager
    from webshare_app.core.config.defaults import DEFAULT_PORT

    bad_file = tmp_path / "webshare_config.json"
    bad_file.write_bytes(b'{"port": 1234, "folder": "\xff\xfe broken"}')
    monkeypatch.setattr(manager_module, "CONFIG_FILE", str(bad_file))
    monkeypatch.setenv("WEBSHARE_CONFIG_DIR", str(tmp_path / "app_config"))
    monkeypatch.setattr(ConfigManager, "_ensure_shared_folder_exists", lambda self: None)

    manager = ConfigManager()

    assert manager.get("port") == DEFAULT_PORT
    backups = list(tmp_path.glob("webshare_config.json.corrupt-*"))
    assert len(backups) == 1


# ISSUE-001: 병합 중 cancel은 409로 거부되어야 함
def test_cancel_chunk_upload_rejects_completing_session(client, login, csrf_headers):
    token = login("admin")
    headers = csrf_headers(token)

    sid = _init_chunk_session(client, token, headers, "cancel-race.txt", 6, 3, 2)
    with upload_session_lock:
        temp_dir = UPLOAD_SESSIONS[sid]["temp_dir"]
        UPLOAD_SESSIONS[sid]["status"] = UPLOAD_STATUS_COMPLETING

    try:
        resp = client.post(
            f"/upload/chunk/{sid}/cancel",
            json={"csrf_token": token},
            headers=headers,
        )
        assert resp.status_code == 409
        assert resp.get_json()["success"] is False
        with upload_session_lock:
            assert sid in UPLOAD_SESSIONS
            assert Path(UPLOAD_SESSIONS[sid]["temp_dir"]).exists()
    finally:
        _cleanup_upload_session(sid, temp_dir=temp_dir)
    assert (Path(conf.get("folder")) / "cancel-race.txt").exists() is False


# ISSUE-001: 세션이 사라진 병합은 커밋을 포기해야 함
def test_complete_aborts_when_session_removed_mid_merge(client, login, csrf_headers, monkeypatch):
    token = login("admin")
    headers = csrf_headers(token)

    sid = _init_chunk_session(client, token, headers, "merge-abort.txt", 6, 3, 2)
    _upload_chunk(client, sid, 0, b"abc", headers)
    _upload_chunk(client, sid, 1, b"def", headers)

    original_copyfileobj = shutil.copyfileobj

    def _copy_then_drop_session(*args, **kwargs):
        from webshare_app.services import upload_service as upload_service_module

        with upload_session_lock:
            upload_service_module.UPLOAD_SESSIONS.pop(sid, None)
        return original_copyfileobj(*args, **kwargs)

    monkeypatch.setattr(shutil, "copyfileobj", _copy_then_drop_session)

    resp = client.post(
        f"/upload/chunk/{sid}/complete",
        json={"csrf_token": token},
        headers=headers,
    )
    assert resp.status_code == 409
    assert resp.get_json()["success"] is False
    assert (Path(conf.get("folder")) / "merge-abort.txt").exists() is False


# ISSUE-005: 여유 공간 부족 시 압축 해제를 거부해야 함
def test_unzip_rejects_when_disk_space_insufficient(client, login, csrf_headers, monkeypatch):
    base = Path(conf.get("folder"))
    archive = base / "big.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("data.bin", b"x" * (256 * 1024))

    monkeypatch.setattr(
        shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(total=10**9, used=10**9, free=1024),
    )

    token = login("admin")
    resp = client.post(
        "/unzip/big.zip",
        json={"csrf_token": token},
        headers=csrf_headers(token),
    )
    assert resp.status_code == 507
    assert resp.get_json()["success"] is False
    assert (base / "big").exists() is False


# ISSUE-005: 실패 시 부분 추출물이 남지 않아야 함
def test_unzip_cleans_partial_dir_on_crc_failure(client, login, csrf_headers):
    base = Path(conf.get("folder"))
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("part1.txt", b"A" * 10000)
        zf.writestr("part2.txt", b"B" * 10000)
    blob = bytearray(raw.getvalue())
    marker = blob.find(b"A" * 4)
    assert marker != -1
    blob[marker] ^= 0xFF
    (base / "crcbad.zip").write_bytes(bytes(blob))

    token = login("admin")
    resp = client.post(
        "/unzip/crcbad.zip",
        json={"csrf_token": token},
        headers=csrf_headers(token),
    )
    assert resp.get_json()["success"] is False
    assert (base / "crcbad").exists() is False
