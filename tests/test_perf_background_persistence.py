"""Background-job / state-persistence cost regressions (area 3).

Guards the confirmed fixes:
- uncapped share-link downloads must not trigger a full link-store rewrite
  per download (hot path); capped links still persist every reservation so
  a crash cannot grant downloads beyond max_downloads.
- duplicate-scan file hashing must stay digest-stable after the chunk-size
  increase (8 KiB -> 256 KiB, fewer read() calls per byte hashed).
"""
from datetime import datetime, timedelta
from hashlib import sha256

from config import SHARE_LINKS, share_links_lock
from features.duplicates import calculate_file_hash, scan_duplicates
from webshare_app.services import share_service


def _seed_link(token, *, max_downloads):
    now = datetime.now()
    with share_links_lock:
        SHARE_LINKS[token] = {
            "path": "shared.bin",
            "expires": now + timedelta(hours=1),
            "created_by": "admin",
            "is_dir": False,
            "password_hash": None,
            "max_downloads": max_downloads,
            "download_count": 0,
            "created_at": now.isoformat(),
        }


def _drop_link(token):
    with share_links_lock:
        SHARE_LINKS.pop(token, None)


def test_uncapped_share_download_skips_full_rewrite(client, monkeypatch):
    calls = {"count": 0}

    def counting_save():
        calls["count"] += 1

    monkeypatch.setattr(share_service, "save_share_links", counting_save)
    _seed_link("free-token", max_downloads=0)
    try:
        for _ in range(5):
            ok, _ = share_service._reserve_share_download("free-token")
            assert ok
        with share_links_lock:
            assert SHARE_LINKS["free-token"]["download_count"] == 5
        assert calls["count"] == 0

        share_service._rollback_reserved_download("free-token")
        with share_links_lock:
            assert SHARE_LINKS["free-token"]["download_count"] == 4
        assert calls["count"] == 0
    finally:
        _drop_link("free-token")


def test_capped_share_download_persists_every_reservation(client, monkeypatch):
    calls = {"count": 0}

    def counting_save():
        calls["count"] += 1

    monkeypatch.setattr(share_service, "save_share_links", counting_save)
    _seed_link("capped-token", max_downloads=2)
    try:
        ok, _ = share_service._reserve_share_download("capped-token")
        assert ok
        ok, _ = share_service._reserve_share_download("capped-token")
        assert ok
        assert calls["count"] == 2

        ok, _ = share_service._reserve_share_download("capped-token")
        assert not ok
        assert calls["count"] == 2

        share_service._rollback_reserved_download("capped-token")
        assert calls["count"] == 3
        with share_links_lock:
            assert SHARE_LINKS["capped-token"]["download_count"] == 1
    finally:
        _drop_link("capped-token")


def test_hash_chunk_size_digest_stable(tmp_path):
    target = tmp_path / "blob.bin"
    target.write_bytes(b"abcdef0123456789" * 65536)  # 1 MiB
    expected = sha256(target.read_bytes()).hexdigest()
    assert calculate_file_hash(str(target)) == expected
    assert calculate_file_hash(str(target), chunk_size=8192) == expected
    assert calculate_file_hash.__defaults__ == (262144,)


def test_duplicate_scan_groups_after_chunk_change(client, tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "a.txt").write_bytes(b"same-content" * 100)
    (root / "b.txt").write_bytes(b"same-content" * 100)
    (root / "c.txt").write_bytes(b"other-content" * 100)
    result = scan_duplicates(str(root), min_size=10)
    groups = result.get("groups", [])
    assert len(groups) == 1
    assert sorted(item["name"] for item in groups[0]["files"]) == ["a.txt", "b.txt"]
