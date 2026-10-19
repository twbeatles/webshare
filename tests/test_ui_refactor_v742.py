"""v7.4.2 ZIP 헤더 인코딩 회귀 테스트 (UI는 v7.4.1로 복원됨)."""
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
