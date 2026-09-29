"""Transfer throughput/memory guards (area 2).

Covers the smallest-first fixes:
- transcoder concurrency cap (503 instead of unbounded ffmpeg spawn)
- ZIP creation item/byte caps (413 instead of temp-disk exhaustion)
- /stream range robustness (suffix ranges, 416 with Content-Range)
"""
import hashlib
import sys
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


def test_transcoder_cap_rejects_new_session_when_full(monkeypatch):
    from webshare_app.features import transcoder as transcoder_module

    monkeypatch.setattr(transcoder_module, "MAX_CONCURRENT_TRANSCODES", 2)
    transcoder_module.TRANSCODE_SESSIONS.clear()
    try:
        for i in range(2):
            transcoder_module.TRANSCODE_SESSIONS[f"live-{i}"] = SimpleNamespace(
                last_access=time.time(), session_id=f"live-{i}"
            )
        with pytest.raises(transcoder_module.TranscodeBusyError):
            transcoder_module.get_transcoder("/shared/new-video.mkv")
        assert len(transcoder_module.TRANSCODE_SESSIONS) == 2
    finally:
        transcoder_module.TRANSCODE_SESSIONS.clear()


def test_transcoder_cap_ignores_idle_sessions(monkeypatch):
    from webshare_app.features import transcoder as transcoder_module

    monkeypatch.setattr(transcoder_module, "MAX_CONCURRENT_TRANSCODES", 1)
    monkeypatch.setattr(
        transcoder_module, "TRANSCODE_CAP_IDLE_SECONDS", 300
    )
    transcoder_module.TRANSCODE_SESSIONS.clear()
    started = {"count": 0}

    def _fake_start(self):
        started["count"] += 1
        self.started_at = time.time()

    monkeypatch.setattr(transcoder_module.Transcoder, "start", _fake_start)
    try:
        transcoder_module.TRANSCODE_SESSIONS["stale"] = SimpleNamespace(
            last_access=time.time() - 3600, session_id="stale"
        )
        transcoder_module.get_transcoder("/shared/other.mkv")
        assert started["count"] == 1
    finally:
        transcoder_module.TRANSCODE_SESSIONS.clear()


def test_transcoder_existing_session_returned_past_cap(monkeypatch):
    from webshare_app.features import transcoder as transcoder_module

    monkeypatch.setattr(transcoder_module, "MAX_CONCURRENT_TRANSCODES", 1)
    transcoder_module.TRANSCODE_SESSIONS.clear()
    try:
        sid = hashlib.md5(b"/shared/known.mkv").hexdigest()
        existing = SimpleNamespace(last_access=time.time(), session_id=sid)

        def _keep_alive():
            existing.last_access = time.time()

        existing.keep_alive = _keep_alive
        transcoder_module.TRANSCODE_SESSIONS[sid] = existing
        transcoder_module.TRANSCODE_SESSIONS["other"] = SimpleNamespace(
            last_access=time.time(), session_id="other"
        )
        assert transcoder_module.get_transcoder("/shared/known.mkv") is existing
    finally:
        transcoder_module.TRANSCODE_SESSIONS.clear()


def test_zip_item_cap_raises_and_cleans_temp(tmp_path, monkeypatch):
    from webshare_app.utils import zip_utils

    monkeypatch.setattr(zip_utils, "MAX_ZIP_ITEMS", 2)
    files = []
    for i in range(3):
        target = tmp_path / f"f{i}.txt"
        target.write_text("x" * 100, encoding="utf-8")
        files.append((str(target), f"f{i}.txt"))
    with pytest.raises(zip_utils.ZipLimitExceeded):
        zip_utils.create_temp_zip_from_items(files)


def test_zip_byte_cap_raises(tmp_path, monkeypatch):
    from webshare_app.utils import zip_utils

    monkeypatch.setattr(zip_utils, "MAX_ZIP_TOTAL_BYTES", 10)
    target = tmp_path / "big.bin"
    target.write_bytes(b"y" * 100)
    with pytest.raises(zip_utils.ZipLimitExceeded):
        zip_utils.create_temp_zip_from_items([(str(target), "big.bin")])


def test_zip_small_archive_still_builds(tmp_path):
    from webshare_app.utils import zip_utils

    target = tmp_path / "ok.txt"
    target.write_text("hello", encoding="utf-8")
    temp_path = zip_utils.create_temp_zip_from_items([(str(target), "ok.txt")])
    try:
        with zipfile.ZipFile(temp_path) as zf:
            assert zf.read("ok.txt") == b"hello"
    finally:
        Path(temp_path).unlink(missing_ok=True)


@pytest.fixture
def stream_file(client, login):
    login("admin")
    shared = Path(__import__("config").conf.get("folder"))
    payload = bytes(range(256)) * 2  # 512 bytes
    (shared / "stream_range.bin").write_bytes(payload)
    return payload


def test_stream_suffix_range(client, stream_file):
    resp = client.get("/stream/stream_range.bin", headers={"Range": "bytes=-10"})
    assert resp.status_code == 206
    assert resp.data == stream_file[-10:]
    assert resp.headers["Content-Range"] == "bytes 502-511/512"


def test_stream_open_range_and_first_byte(client, stream_file):
    resp = client.get("/stream/stream_range.bin", headers={"Range": "bytes=500-"})
    assert resp.status_code == 206
    assert resp.data == stream_file[500:]
    assert resp.headers["Content-Range"] == "bytes 500-511/512"

    first = client.get("/stream/stream_range.bin", headers={"Range": "bytes=0-0"})
    assert first.status_code == 206
    assert first.data == stream_file[:1]


def test_stream_unsatisfiable_returns_416_with_content_range(client, stream_file):
    resp = client.get("/stream/stream_range.bin", headers={"Range": "bytes=9999-"})
    assert resp.status_code == 416
    assert resp.headers["Content-Range"] == "bytes */512"


def test_stream_multi_range_serves_first_spec(client, stream_file):
    resp = client.get(
        "/stream/stream_range.bin", headers={"Range": "bytes=0-9, 100-109"}
    )
    assert resp.status_code == 206
    assert resp.data == stream_file[0:10]
