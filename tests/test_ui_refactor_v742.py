"""v7.4.2 웹 UI 리팩토링 회귀 테스트: ZIP 헤더 인코딩 + 목록 템플릿 구조."""
from pathlib import Path

from config import conf


def test_zip_download_header_is_latin1_safe_for_korean_folder(client, login):
    base = Path(conf.get("folder"))
    (base / "문서").mkdir(parents=True, exist_ok=True)
    (base / "문서" / "a.txt").write_text("a", encoding="utf-8")

    login("admin")
    resp = client.get("/zip/문서")
    assert resp.status_code == 200
    disposition = resp.headers["Content-Disposition"]
    # WSGI 헤더는 latin-1만 허용 — 비ASCII 폴백이 섞이면 전송 중 UnicodeEncodeError
    disposition.encode("latin-1")
    assert "filename*=UTF-8''" in disposition
    resp.close()


def test_file_list_renders_select_all_header_and_folder_zip_action(client, login):
    base = Path(conf.get("folder"))
    (base / "sub").mkdir(parents=True, exist_ok=True)
    (base / "f.txt").write_text("x", encoding="utf-8")

    login("admin")
    html = client.get("/browse/").get_data(as_text=True)
    assert 'id="selectAllCheck"' in html
    assert 'id="batchBar"' in html
    assert 'data-sort="size"' in html
    # 폴더 행은 ZIP 아이콘(다운로드 동작은 /zip 으로 연결)
    assert "fa-file-zipper" in html
