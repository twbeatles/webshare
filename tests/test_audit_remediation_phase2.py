"""PROJECT_AUDIT.md Phase 2 회귀 테스트 (ISSUE-003/004 + GDrive/HTTPS/예약)."""

import shutil
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from config import SHARE_LINKS, conf, share_links_lock

UUID_HEX = "a" * 32  # uuid4().hex 형태의 휴지통 entry id


def _share_token(token, path, is_dir=False):
    with share_links_lock:
        SHARE_LINKS[token] = {
            "path": path,
            "expires": datetime.now() + timedelta(hours=1),
            "created_by": "admin",
            "is_dir": is_dir,
            "password_hash": None,
            "max_downloads": 0,
            "download_count": 0,
            "created_at": datetime.now().isoformat(),
        }


# ISSUE-003: uuid가 포함된 휴지통 파일명에서 원본명을 복원해야 함
def test_trash_extract_strips_uuid_prefix():
    from webshare_app.features.trash import extract_original_name_from_trash

    assert (
        extract_original_name_from_trash(f"20250101_120000_{UUID_HEX}_report.pdf")
        == "report.pdf"
    )
    assert extract_original_name_from_trash("20240101_010101_old.txt") == "old.txt"


# ISSUE-003a: 메타데이터 확정 저장 실패 시 halfway 커밋 금지 (원위치 보존)
def test_move_to_trash_rolls_back_when_confirm_save_fails(client, login, monkeypatch):
    import webshare_app.features.trash as trash_module

    base = Path(conf.get("folder"))
    target = base / "halfway.txt"
    target.write_text("keep me", encoding="utf-8")
    login("admin")

    real_save = trash_module._save_trash_metadata
    calls = {"n": 0}

    def _flaky(metadata):
        calls["n"] += 1
        if calls["n"] in (2, 3):
            raise OSError("disk full")
        return real_save(metadata)

    monkeypatch.setattr(trash_module, "_save_trash_metadata", _flaky)
    ok, _ = trash_module.move_to_trash(str(target))
    assert ok is False
    assert target.exists()
    assert list((base / ".webshare_trash").iterdir()) == []
    # 확정 저장 실패로 남을 수 있는 pending 잔해는 self-heal이 정리한다
    trash_module.self_heal_trash_metadata()
    assert trash_module._load_trash_metadata().get("entries", {}) == {}


# ISSUE-003b: 복원 이동 실패 시 메타데이터 항목을 복구해야 함
def test_restore_keeps_entry_when_move_fails(client, login, monkeypatch):
    import webshare_app.features.trash as trash_module

    base = Path(conf.get("folder"))
    target = base / "restore_me.txt"
    target.write_text("data", encoding="utf-8")
    login("admin")
    ok, trash_name = trash_module.move_to_trash(str(target))
    assert ok is True

    def _boom(*args, **kwargs):
        raise OSError("boom")

    monkeypatch.setattr(shutil, "move", _boom)
    ok, _ = trash_module.restore_from_trash(trash_name)
    assert ok is False
    assert (base / ".webshare_trash" / trash_name).exists()
    assert trash_name in trash_module._load_trash_metadata().get("entries", {})


# ISSUE-003: self-heal이 고아 파일을 재등록하고 고아 메타데이터를 정리해야 함
def test_trash_self_heal_registers_orphan_and_prunes_stale(client, login):
    import webshare_app.features.trash as trash_module

    base = Path(conf.get("folder"))
    trash_dir = base / ".webshare_trash"
    trash_dir.mkdir(parents=True, exist_ok=True)
    orphan = trash_dir / f"20200101_000000_{UUID_HEX}_old.txt"
    orphan.write_text("orphan", encoding="utf-8")
    login("admin")

    meta = trash_module._load_trash_metadata()
    meta.setdefault("entries", {})["ghost.txt"] = {
        "trash_name": "ghost.txt",
        "original_rel_path": "ghost.txt",
    }
    trash_module._save_trash_metadata(meta)

    healed = trash_module.self_heal_trash_metadata()
    assert healed == 1
    entries = trash_module._load_trash_metadata().get("entries", {})
    assert entries[orphan.name]["original_rel_path"] == "old.txt"
    assert "ghost.txt" not in entries

    ok, restored = trash_module.restore_from_trash(orphan.name)
    assert ok is True
    assert Path(restored).name == "old.txt"


# ISSUE-004: 세션/IP 버킷 합산 상한 (횟수)
def test_combined_quota_caps_session_and_ip_buckets(client):
    from utils.helpers import reserve_combined_download_quota

    conf.set("daily_download_limit", 2)
    conf.set("daily_bandwidth_limit_mb", 0)
    ok, _, _ = reserve_combined_download_quota("sid-A", "10.0.0.1", True, 0)
    assert ok is True
    ok, _, _ = reserve_combined_download_quota("", "10.0.0.1", True, 0)
    assert ok is True
    ok, message, _ = reserve_combined_download_quota("sid-A", "10.0.0.1", True, 0)
    assert ok is False
    assert "Daily download limit exceeded" in message


# ISSUE-004: 세션/IP 버킷 합산 상한 (바이트)
def test_combined_quota_caps_bandwidth_bytes(client):
    from utils.helpers import reserve_combined_download_quota

    conf.set("daily_download_limit", 0)
    conf.set("daily_bandwidth_limit_mb", 1)
    ok, _, _ = reserve_combined_download_quota("sid-B", "10.0.0.2", True, 600 * 1024)
    assert ok is True
    ok, _, _ = reserve_combined_download_quota("", "10.0.0.2", True, 300 * 1024)
    assert ok is True
    # 세션 버킷만 보면 600KB + 300KB로 한도(1MB) 이내지만 합산은 초과이므로 거부
    ok, message, _ = reserve_combined_download_quota("sid-B", "10.0.0.2", True, 300 * 1024)
    assert ok is False
    assert "Daily bandwidth limit exceeded" in message


# ISSUE-004: 로그인 사용자의 공유 다운로드는 인증 다운로드와 예산을 공유해야 함
def test_share_download_shares_budget_with_authenticated_download(client, login):
    base = Path(conf.get("folder"))
    (base / "shared.txt").write_text("shared", encoding="utf-8")
    conf.set("daily_download_limit", 1)
    conf.set("daily_bandwidth_limit_mb", 0)
    _share_token("tok-budget", "shared.txt")
    login("admin")

    resp = client.get("/share/tok-budget")
    assert resp.status_code == 200
    over = client.get("/download/shared.txt")
    assert over.status_code == 429


# ISSUE-004: 단건 abort는 전액 유지이므로 429 문구를 분리해야 함
def test_direct_download_429_uses_hold_full_message(client, login):
    from webshare_app.utils.helpers.download_quota import QUOTA_DIRECT_NOTE, QUOTA_POLICY_NOTE

    base = Path(conf.get("folder"))
    (base / "direct.txt").write_text("direct", encoding="utf-8")
    conf.set("daily_download_limit", 1)
    conf.set("daily_bandwidth_limit_mb", 0)
    login("admin")

    assert client.get("/download/direct.txt").status_code == 200
    resp = client.get("/download/direct.txt")
    assert resp.status_code == 429
    body = resp.get_json()["error"]
    assert QUOTA_DIRECT_NOTE in body
    assert QUOTA_POLICY_NOTE not in body


# GDrive: 상태 코드 기반 재시도 (429는 재시도, 400은 즉시 실패)
def test_gdrive_retries_rate_limit_but_not_bad_request(monkeypatch):
    import webshare_app.services.google_drive_client.http as http_module
    from webshare_app.services.cloud_sync_constants import CloudSyncError

    class _Harness(http_module.GoogleDriveHttpMixin):
        def __init__(self, errors):
            self._errors = list(errors)
            self.calls = 0

        def _check_cancelled(self):
            pass

        def _request_response_once(self, *args, **kwargs):
            self.calls += 1
            if self._errors:
                raise self._errors.pop(0)
            return (b"{}", {}, 200)

    monkeypatch.setattr(http_module.time, "sleep", lambda seconds: None)

    harness = _Harness([
        CloudSyncError("google_drive request failed: 429 too many", status=429),
        CloudSyncError("google_drive request failed: 429 too many", status=429),
    ])
    assert harness._request_response("GET", "https://example.com")[2] == 200
    assert harness.calls == 3

    harness = _Harness([CloudSyncError("google_drive request failed: 400 bad", status=400)])
    try:
        harness._request_response("GET", "https://example.com")
        assert False, "400은 재시도 없이 실패해야 함"
    except CloudSyncError:
        pass
    assert harness.calls == 1


# GDrive: Retry-After 존중 + 레거시 메시지 폴백
def test_gdrive_honors_retry_after_and_legacy_status_text(monkeypatch):
    import webshare_app.services.google_drive_client.http as http_module
    from webshare_app.services.cloud_sync_constants import CloudSyncError

    sleeps = []
    monkeypatch.setattr(http_module.time, "sleep", sleeps.append)

    class _Harness(http_module.GoogleDriveHttpMixin):
        def __init__(self, errors):
            self._errors = list(errors)
            self.calls = 0

        def _check_cancelled(self):
            pass

        def _request_response_once(self, *args, **kwargs):
            self.calls += 1
            if self._errors:
                raise self._errors.pop(0)
            return (b"{}", {}, 200)

    harness = _Harness([CloudSyncError("temporary", status=503, retry_after=2)])
    assert harness._request_response("GET", "https://example.com")[2] == 200
    assert sleeps == [2]

    legacy = _Harness([CloudSyncError("google_drive upload failed: 503 boom")])
    assert legacy._request_response("PUT", "https://example.com")[2] == 200
    assert legacy.calls == 2


# adhoc HTTPS: 조용한 HTTP 강등이 아니라 시작 거부해야 함
def test_server_thread_refuses_startup_when_adhoc_unavailable(monkeypatch):
    import importlib.util

    from webshare_app.server.thread import ServerThread

    monkeypatch.setattr(importlib.util, "find_spec", lambda _name: None)
    thread = ServerThread(use_https=True)
    thread.run()
    assert thread.failed_event.is_set()
    assert not thread.ready_event.is_set()
    assert "HTTPS" in thread.startup_error
    assert thread.wait_until_ready(timeout=0.2) is False


# 청크 병합 2배수: init 예약에 병합 버퍼를 반영해야 함
def test_chunk_init_reserves_merge_buffer(client, login, csrf_headers, monkeypatch):
    from webshare_app.services import upload_service as upload_service_module
    from webshare_app.services.upload_service import UPLOAD_FREE_SPACE_BUFFER_BYTES

    total = 10 * 1024 * 1024
    tight = SimpleNamespace(total=10**12, used=0, free=total + UPLOAD_FREE_SPACE_BUFFER_BYTES + 1)
    monkeypatch.setattr(shutil, "disk_usage", lambda _path: tight)

    token = login("admin")
    headers = csrf_headers(token)
    payload = {
        "filename": "merge-big.bin",
        "total_size": total,
        "path": "",
        "chunk_size": 5 * 1024 * 1024,
        "total_chunks": 2,
        "csrf_token": token,
    }
    resp = client.post("/upload/chunk/init", json=payload, headers=headers)
    assert resp.status_code == 507

    roomy = SimpleNamespace(
        total=10**12, used=0, free=2 * total + UPLOAD_FREE_SPACE_BUFFER_BYTES
    )
    monkeypatch.setattr(shutil, "disk_usage", lambda _path: roomy)
    resp = client.post("/upload/chunk/init", json=payload, headers=headers)
    assert resp.status_code == 200
    reserved = sum(
        int(item.get("bytes", 0) or 0)
        for item in upload_service_module._disk_reservations.values()
    )
    assert reserved == 2 * total
