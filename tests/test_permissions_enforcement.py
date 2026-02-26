from pathlib import Path

from config import FOLDER_PERMISSIONS, conf, permissions_lock


def test_read_permission_enforced_on_browse_list_download_stream(client, login):
    base = Path(conf.get("folder"))
    secret_dir = base / "secret"
    secret_dir.mkdir(parents=True, exist_ok=True)
    (secret_dir / "hello.txt").write_text("hello", encoding="utf-8")

    with permissions_lock:
        FOLDER_PERMISSIONS["secret"] = {
            "read": ["admin"],
            "write": ["admin"],
            "delete": ["admin"],
        }

    login("guest")

    assert client.get("/browse/secret").status_code == 403
    assert client.get("/api/list/secret").status_code == 403
    assert client.get("/download/secret/hello.txt").status_code == 403
    assert client.get("/stream/secret/hello.txt").status_code == 403


def test_write_permission_enforced_on_chunk_upload(client, login, csrf_headers):
    base = Path(conf.get("folder"))
    upload_dir = base / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    conf.set("allow_guest_upload", True)

    with permissions_lock:
        FOLDER_PERMISSIONS["uploads"] = {
            "read": ["*"],
            "write": ["admin"],
            "delete": ["admin"],
        }

    token = login("guest")
    resp = client.post(
        "/upload/chunk/init",
        json={
            "filename": "x.txt",
            "total_size": 1,
            "path": "uploads",
            "csrf_token": token,
        },
        headers=csrf_headers(token),
    )

    assert resp.status_code == 403
    body = resp.get_json()
    assert "error" in body
