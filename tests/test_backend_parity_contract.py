"""Backend parity contract tests (PROJECT_AUDIT sections 5-6).

Locks the share-flow browser contract that BOTH backends must satisfy
(Go: ``TestSharePasswordAndLimits``/``TestShareHTMLNegotiation`` in
``go-core/internal/handlers/share_test.go``; Python: this file), the
staging-dir scan exclusions (``.upload_temp``/``.webshare_transcode``),
and backend-selection config handling.

Hermetic: never spawns a real server, never touches user files.
"""

import os
from datetime import datetime, timedelta
from pathlib import Path

from config import SHARE_LINKS, conf, share_links_lock
from webshare_app.features.duplicates import scan_duplicates
from webshare_app.security.auth import hash_password
from webshare_app.utils.file_utils import get_folder_size
from webshare_app.utils.helpers.expiry_cleanup import (
    cleanup_stale_transcode_dirs,
    cleanup_upload_temp_dirs,
)


# -- Share-flow browser contract (Go/Python parity) ----------------------


def _put_share(token, **fields):
    info = {
        "path": "hello.txt",
        "expires": datetime.now() + timedelta(hours=1),
        "created_by": "admin",
        "is_dir": False,
        "password_hash": None,
        "max_downloads": 0,
        "download_count": 0,
        "created_at": datetime.now().isoformat(),
    }
    info.update(fields)
    with share_links_lock:
        SHARE_LINKS[token] = info


def _drop_share(token):
    with share_links_lock:
        SHARE_LINKS.pop(token, None)


def _seed_file():
    Path(conf.get("folder"), "hello.txt").write_text("hi", encoding="utf-8")


def test_share_password_challenge_is_html(client, app):
    """Parity: password link GET => 200 text/html form (not JSON)."""
    _seed_file()
    _put_share("parity-pw", password_hash=hash_password("s3cret"))
    try:
        resp = client.get("/share/parity-pw")
        assert resp.status_code == 200
        assert "text/html" in resp.content_type
        assert "password" in resp.get_data(as_text=True).lower()
    finally:
        _drop_share("parity-pw")


def test_share_wrong_password_rerenders_html(client, app):
    """Parity: wrong password POST => 200 HTML form with an error."""
    _seed_file()
    _put_share("parity-pw2", password_hash=hash_password("s3cret"))
    try:
        resp = client.post("/share/parity-pw2", data={"password": "nope"})
        assert resp.status_code == 200
        assert "text/html" in resp.content_type
    finally:
        _drop_share("parity-pw2")


def test_share_expired_missing_exhausted_are_html(client, app):
    """Parity: expired 410 / missing 404 / exhausted 429 => HTML pages."""
    _seed_file()
    _put_share("parity-old", expires=datetime.now() - timedelta(seconds=1))
    _put_share("parity-max", max_downloads=1, download_count=1)
    try:
        resp = client.get("/share/parity-old")
        assert resp.status_code == 410
        assert "text/html" in resp.content_type

        resp = client.get("/share/parity-max")
        assert resp.status_code == 429
        assert "text/html" in resp.content_type
    finally:
        _drop_share("parity-old")
        _drop_share("parity-max")

    resp = client.get("/share/parity-no-such-token")
    assert resp.status_code == 404
    assert "text/html" in resp.content_type


# -- Staging-dir scan exclusions ------------------------------------------


def _write(path, size):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"q" * size)


def test_folder_size_ignores_staging_dirs(tmp_path):
    """Partial chunks/transcode segments must not inflate folder size."""
    _write(tmp_path / "real.bin", 100)
    _write(tmp_path / ".upload_temp" / "sess" / "chunk_00000", 1000)
    _write(tmp_path / "sub" / ".upload_temp" / "sess" / "chunk_00000", 500)
    _write(tmp_path / ".webshare_transcode" / "sid" / "seg_0.ts", 1000)
    assert get_folder_size(str(tmp_path), use_cache=False) == 100


def test_duplicate_scan_ignores_upload_temp(tmp_path, app):
    """Partial chunks must not appear in duplicate results."""
    scan_root = tmp_path / "scan"
    blob = b"y" * 256
    (scan_root / "a").mkdir(parents=True)
    (scan_root / "b").mkdir(parents=True)
    (scan_root / "a" / "f1.bin").write_bytes(blob)
    (scan_root / "b" / "f2.bin").write_bytes(blob)
    temp = scan_root / ".upload_temp" / "sess"
    temp.mkdir(parents=True)
    (temp / "c1.bin").write_bytes(blob)
    (temp / "c2.bin").write_bytes(blob)

    result = scan_duplicates(str(scan_root), min_size=100)
    groups = result.get("groups", [])
    assert len(groups) == 1
    for group in groups:
        for item in group["files"]:
            assert ".upload_temp" not in item["path"]


def test_startup_transcode_cleanup_keeps_fresh_dirs(tmp_path):
    """Stale transcode orphans are removed; fresh ones are kept."""
    root = tmp_path / ".webshare_transcode"
    old = root / "old-sid"
    fresh = root / "fresh-sid"
    old.mkdir(parents=True)
    fresh.mkdir(parents=True)
    aged = datetime.now().timestamp() - 30 * 3600
    os.utime(old, (aged, aged))

    removed = cleanup_stale_transcode_dirs(str(tmp_path), max_age_hours=24.0)
    assert removed == 1
    assert not old.exists()
    assert fresh.exists()


def test_startup_cleanup_missing_root_is_noop(tmp_path):
    assert cleanup_stale_transcode_dirs(str(tmp_path / "nope")) == 0
    assert cleanup_upload_temp_dirs(str(tmp_path / "nope")) == 0


# -- Backend-selection config respect -------------------------------------


def test_backend_name_defaults_to_go(monkeypatch):
    from webshare_app.server import go_process

    monkeypatch.delenv(go_process.BACKEND_ENV, raising=False)
    assert go_process.backend_name() == "go"


def test_backend_name_honors_env(monkeypatch):
    import webshare_app.server as srv
    from webshare_app.server import go_process

    monkeypatch.setenv(go_process.BACKEND_ENV, "python")
    assert go_process.backend_name() == "python"
    assert srv._use_go_backend() is False

    monkeypatch.setenv(go_process.BACKEND_ENV, "  GO  ")
    assert go_process.backend_name() == "go"
    assert srv._use_go_backend() is True

    monkeypatch.setenv(go_process.BACKEND_ENV, "")
    assert go_process.backend_name() == "go"
