from datetime import datetime, timedelta
from pathlib import Path

from config import SHARE_LINKS, conf, share_links_lock


class _DummyTranscoder:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.playlist_path = str(Path(output_dir) / "index.m3u8")


def test_download_limits_applied_to_file_zip_batch_share_and_hls(client, login, csrf_headers, monkeypatch, tmp_path):
    base = Path(conf.get("folder"))
    (base / "folder").mkdir(parents=True, exist_ok=True)
    (base / "folder" / "a.txt").write_text("a", encoding="utf-8")
    (base / "file.txt").write_text("file", encoding="utf-8")
    (base / "video.mkv").write_bytes(b"video")

    hls_dir = tmp_path / "hls"
    hls_dir.mkdir(parents=True, exist_ok=True)
    (hls_dir / "segment_000.ts").write_bytes(b"segment")

    monkeypatch.setattr("utils.helpers.check_download_limit", lambda _ip, _count_event=True: (False, "limit exceeded"))
    monkeypatch.setattr("utils.helpers.track_download", lambda _ip, _size, _count_event=True: None)
    monkeypatch.setattr("features.transcoder.get_transcoder", lambda _path: _DummyTranscoder(str(hls_dir)))

    token = login("admin")
    headers = csrf_headers(token)

    assert client.get("/download/file.txt").status_code == 429
    assert client.get("/zip/folder").status_code == 429

    batch = client.post(
        "/batch_download/folder",
        data={"files": '["a.txt"]'},
        headers=headers,
    )
    assert batch.status_code == 429

    with share_links_lock:
        SHARE_LINKS["tok-file"] = {
            "path": "file.txt",
            "expires": datetime.now() + timedelta(hours=1),
            "created_by": "admin",
            "is_dir": False,
            "password_hash": None,
            "max_downloads": 0,
            "download_count": 0,
            "created_at": datetime.now().isoformat(),
        }
        SHARE_LINKS["tok-dir"] = {
            "path": "folder",
            "expires": datetime.now() + timedelta(hours=1),
            "created_by": "admin",
            "is_dir": True,
            "password_hash": None,
            "max_downloads": 0,
            "download_count": 0,
            "created_at": datetime.now().isoformat(),
        }

    assert client.get("/share/tok-file").status_code == 429
    assert client.get("/share/tok-dir").status_code == 429

    hls_resp = client.get("/stream/hls/video.mkv/segment_000.ts")
    assert hls_resp.status_code == 429
