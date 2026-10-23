"""구 UI(v7.4.1 복원) 수리 회귀 테스트: 폴더 ZIP 분기, 선택 해제, 최상위 일괄 다운로드."""
from pathlib import Path

from config import conf

ROOT_DIR = Path(__file__).resolve().parents[1]


def _read_scripts():
    return (ROOT_DIR / "templates" / "partials" / "scripts.html").read_text(
        encoding="utf-8"
    )


def test_folder_download_routes_to_zip():
    body = _read_scripts()
    # downloadItem이 폴더 여부를 받아 /zip/ 과 /download/ 를 분기한다
    assert "function downloadItem(path, isDir)" in body
    assert "(isDir ? '/zip/' : '/download/')" in body
    # 컨텍스트 메뉴 다운로드가 폴더 여부를 전달한다
    assert "downloadItem(ctxTarget.path, ctxTarget.type === 'folder')" in body
    boot = (ROOT_DIR / "templates" / "partials" / "boot_state.html").read_text(
        encoding="utf-8"
    )
    assert "return downloadItem(path, isDir);" in boot


def test_clear_selection_resets_batch_state():
    body = _read_scripts()
    assert "selectedFiles.clear();" in body
    assert "updateBatchUI();" in body
    # 존재하지 않는 updateBatchBar 호출이 남아 있으면 Esc에서 ReferenceError
    assert "updateBatchBar(" not in body


def test_batch_download_handles_single_and_top_level():
    body = _read_scripts()
    # 1건 선택은 ZIP 묶음 없이 직접 다운로드
    assert "if (rows.length === 1)" in body
    # 최상위 포함 다건은 /batch_download/ ZIP 한 번 (서버가 루트를 지원)
    assert "} else if (currentPath) {" not in body
    assert "index * 500" not in body


def test_batch_download_supports_root(client, login, csrf_headers):
    base = Path(conf.get("folder"))
    (base / "one.txt").write_text("1", encoding="utf-8")
    (base / "two.txt").write_text("2", encoding="utf-8")
    token = login("admin")

    res = client.post(
        "/batch_download/",
        data={"files": '["one.txt", "two.txt"]', "csrf_token": token},
        headers=csrf_headers(token),
    )

    assert res.status_code == 200
    assert res.headers["Content-Type"].startswith("application/zip")


def test_download_rejects_directory_but_zip_serves_it(client, login):
    base = Path(conf.get("folder"))
    (base / "sub").mkdir(parents=True, exist_ok=True)
    (base / "sub" / "a.txt").write_text("a", encoding="utf-8")

    login("admin")
    # 위 JS 분기가 의존하는 백엔드 계약: 폴더는 /download 400, /zip 200
    assert client.get("/download/sub").status_code == 400
    assert client.get("/zip/sub").status_code == 200


def test_toolbar_zip_link_encodes_current_path(client, login):
    # '#' 등이 들어간 폴더에서 현재 폴더 ZIP 링크가 잘리지 않아야 한다 (audit ISSUE-011)
    base = Path(conf.get("folder"))
    (base / "C# notes").mkdir(parents=True, exist_ok=True)
    (base / "C# notes" / "a.txt").write_text("a", encoding="utf-8")

    login("admin")
    page = client.get("/browse/C%23%20notes").get_data(as_text=True)

    assert 'href="/zip/C%23%20notes"' in page
    assert client.get("/zip/C%23%20notes").status_code == 200
