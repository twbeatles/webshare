"""PROJECT_AUDIT.md Phase 3 회귀 테스트 (WebDAV TTL + 문서 정합성)."""

from datetime import datetime, timedelta
from pathlib import Path

import pytest

import webshare_app.features.webdav_server as webdav_module

ROOT_DIR = Path(__file__).resolve().parents[1]


@pytest.fixture
def clean_webdav_attempts():
    """WebDAV 인증 시도 기록을 테스트 전후로 비운다 (순서 독립성 보장)."""
    with webdav_module._webdav_auth_lock:
        webdav_module._webdav_auth_attempts.clear()
    yield
    with webdav_module._webdav_auth_lock:
        webdav_module._webdav_auth_attempts.clear()


# WebDAV: 차단 한도 미만 실패 기록도 TTL이 지나면 정리되어야 함
def test_webdav_sub_threshold_attempts_expire(clean_webdav_attempts):
    for _ in range(3):
        webdav_module._record_auth_attempt("10.9.0.1", False)
    for _ in range(2):
        webdav_module._record_auth_attempt("10.9.0.2", False)
    # 10.9.0.1의 기록만 25시간 전으로 되돌린다
    with webdav_module._webdav_auth_lock:
        webdav_module._webdav_auth_attempts["10.9.0.1"]["last_attempt"] = (
            datetime.now() - timedelta(hours=25)
        )

    cleaned = webdav_module.cleanup_expired_webdav_auth_attempts()

    assert cleaned == 1
    assert "10.9.0.1" not in webdav_module._webdav_auth_attempts
    assert "10.9.0.2" in webdav_module._webdav_auth_attempts


# WebDAV: 차단 만료 항목은 정리되어야 하고, 유효한 차단은 유지되어야 함
def test_webdav_expired_block_cleaned_but_active_block_kept(clean_webdav_attempts):
    with webdav_module._webdav_auth_lock:
        webdav_module._webdav_auth_attempts["10.9.0.3"] = {
            "attempts": 8,
            "blocked_until": datetime.now() - timedelta(minutes=1),
            "last_attempt": datetime.now() - timedelta(minutes=11),
        }
        webdav_module._webdav_auth_attempts["10.9.0.4"] = {
            "attempts": 8,
            "blocked_until": datetime.now() + timedelta(minutes=9),
            "last_attempt": datetime.now(),
        }

    cleaned = webdav_module.cleanup_expired_webdav_auth_attempts()

    assert cleaned == 1
    assert "10.9.0.3" not in webdav_module._webdav_auth_attempts
    assert "10.9.0.4" in webdav_module._webdav_auth_attempts


# WebDAV: 실패 기록에 TTL 기준 시각이 남아야 함 + 성공 시 기록 삭제 (기존 동작 고정)
def test_webdav_failure_records_last_attempt_and_success_clears(clean_webdav_attempts):
    webdav_module._record_auth_attempt("10.9.0.5", False)

    item = webdav_module._webdav_auth_attempts["10.9.0.5"]
    assert item["attempts"] == 1
    assert isinstance(item.get("last_attempt"), datetime)

    webdav_module._record_auth_attempt("10.9.0.5", True)
    assert "10.9.0.5" not in webdav_module._webdav_auth_attempts


# WebDAV: 주기 정리(cleanup.py)와 동일한 import 경로로 정리 함수가 노출되어야 함
def test_webdav_cleanup_reachable_from_periodic_cleanup_path():
    from features.webdav_server import cleanup_expired_webdav_auth_attempts

    assert callable(cleanup_expired_webdav_auth_attempts)

    import webshare_app.server.cleanup as cleanup_module
    import inspect

    assert "cleanup_expired_webdav_auth_attempts" in inspect.getsource(cleanup_module)


# 문서 정합성: 버전 단일 진실 공급원 (APP_VERSION in defaults.py)
def test_version_single_source():
    from webshare_app.core.config.defaults import APP_TITLE, APP_VERSION

    assert APP_VERSION == "7.4.3"
    assert APP_VERSION in APP_TITLE

    main_doc = (ROOT_DIR / "main.py").read_text(encoding="utf-8")
    assert "7.3.0" not in main_doc  # 구버전 표기 잔재 금지
    assert "7.4.0" not in main_doc  # 구버전 표기 잔재 금지

    readme_ko = (ROOT_DIR / "README.md").read_text(encoding="utf-8")
    assert f"v{APP_VERSION}" in readme_ko  # README 배지/제목과 일치

    for spec_name in ("WebSharePro.spec", "webshare.spec"):
        spec_text = (ROOT_DIR / spec_name).read_text(encoding="utf-8")
        assert "webshare_app/core/config/defaults.py" in spec_text


# 문서 정합성: Docker는 Python 백엔드 직접 서빙임을 README에 명시
def test_docker_docs_state_python_backend():
    readme_ko = (ROOT_DIR / "README.md").read_text(encoding="utf-8")
    assert "docker_entrypoint.py" in readme_ko
    assert "Python 백엔드" in readme_ko

    readme_en = (ROOT_DIR / "README_EN.md").read_text(encoding="utf-8")
    assert "docker_entrypoint.py" in readme_en
    assert "Python backend" in readme_en

    dockerfile = (ROOT_DIR / "Dockerfile").read_text(encoding="utf-8")
    assert "golang" not in dockerfile.lower()
    assert "go build" not in dockerfile.lower()

    entrypoint = (ROOT_DIR / "docker_entrypoint.py").read_text(encoding="utf-8")
    assert "go_process" not in entrypoint
    assert "make_server" in entrypoint
