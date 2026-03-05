import io
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

from config import (
    BOOKMARKS,
    FAVORITE_FOLDERS,
    FILE_TAGS,
    FOLDER_PERMISSIONS,
    SHARE_LINKS,
    conf,
    metadata_lock,
    permissions_lock,
    share_links_lock,
)


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



def test_metadata_list_endpoints_filter_unreadable_paths(client, login):
    base = Path(conf.get("folder"))
    (base / "public").mkdir(parents=True, exist_ok=True)
    (base / "public" / "a.txt").write_text("ok", encoding="utf-8")
    (base / "secret").mkdir(parents=True, exist_ok=True)
    (base / "secret" / "b.txt").write_text("nope", encoding="utf-8")

    with permissions_lock:
        FOLDER_PERMISSIONS["secret"] = {
            "read": ["admin"],
            "write": ["admin"],
            "delete": ["admin"],
        }

    with metadata_lock:
        FILE_TAGS.clear()
        FILE_TAGS.update(
            {
                "public/a.txt": [{"tag": "visible", "color": "#00ff00"}],
                "secret/b.txt": [{"tag": "hidden", "color": "#ff0000"}],
            }
        )
        FAVORITE_FOLDERS.clear()
        FAVORITE_FOLDERS.extend(
            [
                {"path": "public", "name": "public", "added": "now"},
                {"path": "secret", "name": "secret", "added": "now"},
            ]
        )
        BOOKMARKS.clear()
        BOOKMARKS.extend(
            [
                {"path": "public/a.txt", "name": "a", "added": "now"},
                {"path": "secret/b.txt", "name": "b", "added": "now"},
            ]
        )

    login("guest")

    tags_resp = client.get("/api/tags")
    assert tags_resp.status_code == 200
    all_tags = tags_resp.get_json().get("all_tags", {})
    assert "public/a.txt" in all_tags
    assert "secret/b.txt" not in all_tags

    fav_resp = client.get("/api/favorites")
    assert fav_resp.status_code == 200
    favorite_paths = [item.get("path") for item in fav_resp.get_json().get("favorites", [])]
    assert "public" in favorite_paths
    assert "secret" not in favorite_paths

    bookmarks_resp = client.get("/bookmarks")
    assert bookmarks_resp.status_code == 200
    bookmark_paths = [item.get("path") for item in bookmarks_resp.get_json().get("bookmarks", [])]
    assert "public/a.txt" in bookmark_paths
    assert "secret/b.txt" not in bookmark_paths
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


