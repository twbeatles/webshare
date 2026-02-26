import io
from pathlib import Path

from config import conf


def test_chunk_complete_rejects_empty_upload(client, login, csrf_headers):
    token = login("admin")
    headers = csrf_headers(token)

    init = client.post(
        "/upload/chunk/init",
        json={
            "filename": "empty.txt",
            "total_size": 10,
            "path": "",
            "chunk_size": 5,
            "total_chunks": 2,
            "csrf_token": token,
        },
        headers=headers,
    )
    assert init.status_code == 200
    sid = init.get_json()["session_id"]

    complete = client.post(
        f"/upload/chunk/{sid}/complete",
        json={"csrf_token": token},
        headers=headers,
    )
    assert complete.status_code == 400
    assert (Path(conf.get("folder")) / "empty.txt").exists() is False


def test_chunk_complete_rejects_missing_chunk_index(client, login, csrf_headers):
    token = login("admin")
    headers = csrf_headers(token)

    init = client.post(
        "/upload/chunk/init",
        json={
            "filename": "missing.txt",
            "total_size": 6,
            "path": "",
            "chunk_size": 3,
            "total_chunks": 2,
            "csrf_token": token,
        },
        headers=headers,
    )
    sid = init.get_json()["session_id"]

    upload = client.post(
        f"/upload/chunk/{sid}",
        data={"index": "0", "chunk": (io.BytesIO(b"abc"), "chunk.bin")},
        content_type="multipart/form-data",
        headers=headers,
    )
    assert upload.status_code == 200

    complete = client.post(
        f"/upload/chunk/{sid}/complete",
        json={"csrf_token": token},
        headers=headers,
    )
    assert complete.status_code == 400
    assert (Path(conf.get("folder")) / "missing.txt").exists() is False


def test_chunk_complete_success_with_size_validation(client, login, csrf_headers):
    token = login("admin")
    headers = csrf_headers(token)

    init = client.post(
        "/upload/chunk/init",
        json={
            "filename": "ok.txt",
            "total_size": 6,
            "path": "",
            "chunk_size": 3,
            "total_chunks": 2,
            "csrf_token": token,
        },
        headers=headers,
    )
    sid = init.get_json()["session_id"]

    for index, data in [(0, b"abc"), (1, b"def")]:
        resp = client.post(
            f"/upload/chunk/{sid}",
            data={"index": str(index), "chunk": (io.BytesIO(data), "chunk.bin")},
            content_type="multipart/form-data",
            headers=headers,
        )
        assert resp.status_code == 200

    complete = client.post(
        f"/upload/chunk/{sid}/complete",
        json={"csrf_token": token},
        headers=headers,
    )
    assert complete.status_code == 200
    body = complete.get_json()
    assert body.get("success") is True

    merged = (Path(conf.get("folder")) / "ok.txt").read_bytes()
    assert merged == b"abcdef"

