"""Request hot-path performance/scalability regressions (area 1).

Bounds are call-count based (deterministic) plus one generous time bound.
Synthetic trees only; no commits, no network.
"""

import os
import sys
import time
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from webshare_app.utils import listing as listing_module
from webshare_app.utils.file_utils import (
    get_folder_size,
    invalidate_folder_size_cache,
    invalidate_folder_size_cache_hook,
)


def _seed_files(directory: Path, count: int, prefix: str = "file") -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        (directory / f"{prefix}_{i:05d}.txt").write_text("x", encoding="utf-8")


def _clear_listing_caches() -> None:
    listing_module._list_cache.clear()
    listing_module._list_base_cache.clear()


@pytest.fixture
def big_dir(tmp_path):
    target = tmp_path / "big"
    _seed_files(target, 2000)
    _clear_listing_caches()
    yield target
    _clear_listing_caches()


@pytest.fixture
def scandir_counter(monkeypatch):
    calls = {"count": 0}
    real_scandir = os.scandir

    def counting_scandir(path):
        calls["count"] += 1
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", counting_scandir)
    return calls


def test_second_page_reuses_single_scan(big_dir, scandir_counter):
    first = listing_module.list_directory_page(
        base_dir=str(big_dir), subpath="", page=1, page_size=200,
        cache_scope="perf",
    )
    second = listing_module.list_directory_page(
        base_dir=str(big_dir), subpath="", page=2, page_size=200,
        cache_scope="perf",
    )
    assert first["success"] and second["success"]
    assert scandir_counter["count"] == 1
    assert first["pagination"]["total_count"] == 2000
    assert second["pagination"]["page"] == 2
    first_names = [item["name"] for item in first["items"]]
    second_names = [item["name"] for item in second["items"]]
    assert not set(first_names) & set(second_names)
    assert first_names == sorted(first_names, key=str.lower)
    assert second_names == sorted(second_names, key=str.lower)


def test_query_served_from_base_without_rescan(big_dir, scandir_counter):
    listing_module.list_directory_page(
        base_dir=str(big_dir), subpath="", page=1, page_size=200,
        cache_scope="perf",
    )
    assert scandir_counter["count"] == 1
    filtered = listing_module.list_directory_page(
        base_dir=str(big_dir), subpath="", page=1, page_size=200,
        query="file_000", cache_scope="perf",
    )
    assert filtered["success"]
    assert scandir_counter["count"] == 1
    assert filtered["pagination"]["total_count"] == 100
    assert all("file_000" in item["name"] for item in filtered["items"])


def test_base_hit_matches_fresh_scan_shape(big_dir):
    def caps(rel, is_dir, item_type):
        return {"read": True}
    fresh = listing_module.list_directory_page(
        base_dir=str(big_dir), subpath="", page=2, page_size=200,
        sort_by="name", order="desc", capability_resolver=caps,
        cache_scope="perf",
    )
    listing_module._list_cache.clear()  # keep base, drop page cache
    replay = listing_module.list_directory_page(
        base_dir=str(big_dir), subpath="", page=2, page_size=200,
        sort_by="name", order="desc", capability_resolver=caps,
        cache_scope="perf",
    )
    assert replay == fresh
    assert "name_lower" not in replay["items"][0]
    assert replay["items"][0]["capabilities"] == {"read": True}


def test_warm_second_page_time_bound(big_dir):
    listing_module.list_directory_page(
        base_dir=str(big_dir), subpath="", page=1, page_size=200,
        cache_scope="perf",
    )
    started = time.perf_counter()
    second = listing_module.list_directory_page(
        base_dir=str(big_dir), subpath="", page=2, page_size=200,
        cache_scope="perf",
    )
    elapsed = time.perf_counter() - started
    assert second["success"]
    assert elapsed < 2.0


def test_folder_size_hook_invalidates_on_successful_mutation(app, tmp_path):
    target = tmp_path / "sized"
    _seed_files(target, 3)
    invalidate_folder_size_cache(str(target))

    size_before = get_folder_size(str(target))
    (target / "new_file.txt").write_text("yyyy", encoding="utf-8")
    assert get_folder_size(str(target)) == size_before  # stale TTL cache

    class _Response:
        status_code = 200

    with app.test_request_context("/", method="POST"):
        assert invalidate_folder_size_cache_hook(_Response()) is not None
    assert get_folder_size(str(target)) == size_before + 4


def test_folder_size_hook_keeps_cache_on_read_or_failure(app, tmp_path):
    target = tmp_path / "sized2"
    _seed_files(target, 3)
    invalidate_folder_size_cache(str(target))

    size_before = get_folder_size(str(target))
    (target / "another.txt").write_text("zz", encoding="utf-8")

    class _Response:
        def __init__(self, status):
            self.status_code = status

    with app.test_request_context("/", method="GET"):
        invalidate_folder_size_cache_hook(_Response(200))
    assert get_folder_size(str(target)) == size_before

    with app.test_request_context("/", method="POST"):
        invalidate_folder_size_cache_hook(_Response(500))
    assert get_folder_size(str(target)) == size_before


def test_mutation_blueprints_register_invalidation_hook(app):
    for blueprint_name in ("file", "trash", "upload"):
        funcs = app.after_request_funcs.get(blueprint_name, [])
        assert invalidate_folder_size_cache_hook in funcs, blueprint_name


def test_large_success_listing_skips_json_reparse(client, login, monkeypatch):
    from flask.wrappers import Response as FlaskResponse

    login("admin")
    shared = Path(__import__("config").conf.get("folder"))
    _seed_files(shared / "perf_big", 300)

    calls = {"count": 0}
    real_get_json = FlaskResponse.get_json

    def counting_get_json(self, *args, **kwargs):
        calls["count"] += 1
        return real_get_json(self, *args, **kwargs)

    monkeypatch.setattr(FlaskResponse, "get_json", counting_get_json)
    response = client.get("/api/list/perf_big?page_size=200")
    assert response.status_code == 200
    import json as _json

    payload = _json.loads(response.data)
    assert payload["pagination"]["total_count"] == 300
    assert len(response.data) > 8192
    assert calls["count"] == 0


def test_small_error_shaped_body_still_normalized(client, login):
    login("admin")
    response = client.get("/search?q=a")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["results"] == []
    assert payload["success"] is False
    assert payload["code"] == "ERROR"
    assert payload["request_id"]
