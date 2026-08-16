from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from webshare_app.core.update_installer import (
    UpdateApplyError,
    apply_staged_update,
    cleanup_update_backups,
    consume_update_result,
    prepare_staged_update,
    update_result_path,
    write_update_result,
)
from webshare_app.core.update_manifest import ReleaseManifest


def test_prepare_staged_update_success(tmp_path: Path):
    content = b"sample update binary content"
    sha256 = hashlib.sha256(content).hexdigest()
    manifest = ReleaseManifest(
        version="7.3.0",
        artifact_url="https://example.invalid/WebSharePro.exe",
        artifact_sha256=sha256,
        artifact_size=len(content),
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        signature="dummy",
    )

    staging_root = tmp_path / "updates"
    staged = prepare_staged_update(
        manifest,
        chunks=[content],
        staging_root=staging_root,
        approve=lambda _m, _p: True,
    )
    assert staged is not None
    assert staged.is_file()
    assert staged.read_bytes() == content


def test_prepare_staged_update_hash_mismatch(tmp_path: Path):
    content = b"sample content"
    manifest = ReleaseManifest(
        version="7.3.0",
        artifact_url="https://example.invalid/WebSharePro.exe",
        artifact_sha256="0" * 64,
        artifact_size=len(content),
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        signature="dummy",
    )

    staging_root = tmp_path / "updates"
    with pytest.raises(ValueError, match="Update artifact hash mismatch"):
        prepare_staged_update(
            manifest,
            chunks=[content],
            staging_root=staging_root,
            approve=lambda _m, _p: True,
        )


def test_apply_staged_update_success(tmp_path: Path):
    target = tmp_path / "WebSharePro.exe"
    target.write_bytes(b"original binary")

    staged_content = b"new updated binary"
    staged = tmp_path / "update_staged.exe"
    staged.write_bytes(staged_content)

    backup = tmp_path / "WebSharePro.exe.v7.2.4.bak"
    sha256 = hashlib.sha256(staged_content).hexdigest()

    apply_staged_update(
        target=target,
        staged=staged,
        backup=backup,
        expected_sha256=sha256,
        expected_size=len(staged_content),
        smoke_runner=lambda _p: True,
    )

    assert target.read_bytes() == staged_content
    assert backup.read_bytes() == b"original binary"
    assert not staged.exists()


def test_apply_staged_update_smoke_fail_rollback(tmp_path: Path):
    target = tmp_path / "WebSharePro.exe"
    target.write_bytes(b"original binary")

    staged_content = b"bad new binary"
    staged = tmp_path / "update_staged.exe"
    staged.write_bytes(staged_content)

    backup = tmp_path / "WebSharePro.exe.v7.2.4.bak"
    sha256 = hashlib.sha256(staged_content).hexdigest()

    with pytest.raises(UpdateApplyError, match="Update failed and was rolled back"):
        apply_staged_update(
            target=target,
            staged=staged,
            backup=backup,
            expected_sha256=sha256,
            expected_size=len(staged_content),
            smoke_runner=lambda _p: False,
        )

    # Rollback verification
    assert target.read_bytes() == b"original binary"


def test_update_result_flow(tmp_path: Path):
    result_file = update_result_path(tmp_path)
    assert consume_update_result(result_file) is None

    write_update_result(result_file, {"status": "applied", "version": "7.3.0"})
    data = consume_update_result(result_file)
    assert data is not None
    assert data["status"] == "applied"
    assert data["version"] == "7.3.0"

    # Consumed should delete the file
    assert consume_update_result(result_file) is None


def test_cleanup_update_backups(tmp_path: Path):
    target = tmp_path / "WebSharePro.exe"
    target.write_bytes(b"bin")

    bak1 = tmp_path / "WebSharePro.exe.v7.2.1.bak"
    bak2 = tmp_path / "WebSharePro.exe.v7.2.2.bak"
    bak3 = tmp_path / "WebSharePro.exe.v7.2.3.bak"
    bak1.write_bytes(b"1")
    bak2.write_bytes(b"2")
    bak3.write_bytes(b"3")

    cleanup_update_backups(target, keep_count=2)
    backups = list(tmp_path.glob("*.bak"))
    assert len(backups) <= 2
