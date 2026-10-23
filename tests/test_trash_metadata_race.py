"""Concurrent trash moves keep every metadata entry (audit ISSUE-004)."""

import os
import threading
from pathlib import Path

from config import conf
from webshare_app.features.trash import _load_trash_metadata, move_to_trash, restore_from_trash


def test_concurrent_move_to_trash_keeps_all_entries(app):
    root = Path(conf.get("folder"))
    docs = root / "docs"
    docs.mkdir(exist_ok=True)
    count = 20
    for i in range(count):
        (docs / f"f{i}.txt").write_text("x", encoding="utf-8")

    barrier = threading.Barrier(count)
    results: list[tuple[bool, str]] = [(False, "")] * count

    def worker(i):
        barrier.wait()
        results[i] = move_to_trash(str(docs / f"f{i}.txt"))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(ok for ok, _ in results), results
    entries = _load_trash_metadata()["entries"]
    assert len(entries) == count
    assert not any(entry.get("pending") for entry in entries.values())

    for trash_name in list(entries):
        ok, restored = restore_from_trash(trash_name)
        assert ok, restored
        rel = os.path.relpath(restored, root).replace("\\", "/")
        assert rel.startswith("docs/f"), rel
    assert _load_trash_metadata()["entries"] == {}
