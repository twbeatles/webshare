import io
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

from config import FOLDER_PERMISSIONS, SHARE_LINKS, conf, permissions_lock, share_links_lock


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


def test_restricted_child_hidden_from_parent_listing(client, login):
    base = Path(conf.get("folder"))
    (base / "parent").mkdir(parents=True, exist_ok=True)
    (base / "parent" / "visible.txt").write_text("ok", encoding="utf-8")
    (base / "parent" / "secret").mkdir(parents=True, exist_ok=True)
    (base / "parent" / "secret" / "nope.txt").write_text("nope", encoding="utf-8")

    with permissions_lock:
        FOLDER_PERMISSIONS["parent/secret"] = {
            "read": ["admin"],
            "write": ["admin"],
            "delete": ["admin"],
        }

    login("guest")
    resp = client.get("/api/list/parent")
    assert resp.status_code == 200
    payload = resp.get_json()
    names = [item.get("name") for item in payload.get("items", [])]
    assert "visible.txt" in names
    assert "secret" not in names


def test_zip_excludes_restricted_and_protected_files(client, login):
    base = Path(conf.get("folder"))
    (base / "parent").mkdir(parents=True, exist_ok=True)
    (base / "parent" / "visible.txt").write_text("ok", encoding="utf-8")
    (base / "parent" / ".webshare_hidden.txt").write_text("hidden", encoding="utf-8")
    (base / "parent" / "secret").mkdir(parents=True, exist_ok=True)
    (base / "parent" / "secret" / "nope.txt").write_text("nope", encoding="utf-8")

    with permissions_lock:
        FOLDER_PERMISSIONS["parent/secret"] = {
            "read": ["admin"],
            "write": ["admin"],
            "delete": ["admin"],
        }

    login("guest")
    resp = client.get("/zip/parent")
    assert resp.status_code == 200

    data = b"".join(resp.response)
    with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
        names = sorted(zf.namelist())
    assert "visible.txt" in names
    assert ".webshare_hidden.txt" not in names
    assert "secret/nope.txt" not in names


def test_share_dir_zip_excludes_restricted_and_protected_files(client):
    base = Path(conf.get("folder"))
    (base / "parent").mkdir(parents=True, exist_ok=True)
    (base / "parent" / "visible.txt").write_text("ok", encoding="utf-8")
    (base / "parent" / ".webshare_hidden.txt").write_text("hidden", encoding="utf-8")
    (base / "parent" / "secret").mkdir(parents=True, exist_ok=True)
    (base / "parent" / "secret" / "nope.txt").write_text("nope", encoding="utf-8")

    with permissions_lock:
        FOLDER_PERMISSIONS["parent/secret"] = {
            "read": ["admin"],
            "write": ["admin"],
            "delete": ["admin"],
        }
    with share_links_lock:
        SHARE_LINKS.clear()
        SHARE_LINKS["tok-share"] = {
            "path": "parent",
            "expires": datetime.now() + timedelta(hours=1),
            "created_by": "admin",
            "is_dir": True,
            "password_hash": None,
            "max_downloads": 0,
            "download_count": 0,
            "created_at": datetime.now().isoformat(),
        }

    resp = client.get("/share/tok-share")
    assert resp.status_code == 200
    data = b"".join(resp.response)
    with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
        names = sorted(zf.namelist())
    assert "parent/visible.txt" in names
    assert "parent/.webshare_hidden.txt" not in names
    assert "parent/secret/nope.txt" not in names
