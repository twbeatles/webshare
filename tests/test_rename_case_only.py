"""Case-only renames are not treated as name conflicts (audit §5 gap)."""

from pathlib import Path

from config import conf


def test_case_only_rename_succeeds(client, login, csrf_headers):
    base = Path(conf.get("folder"))
    (base / "report.txt").write_text("r", encoding="utf-8")
    token = login("admin")

    res = client.post("/rename/report.txt", json={"name": "Report.txt", "csrf_token": token},
                      headers=csrf_headers(token))

    assert res.status_code == 200, res.get_json()
    assert "Report.txt" in {p.name for p in base.iterdir()}


def test_rename_to_other_existing_name_is_refused(client, login, csrf_headers):
    base = Path(conf.get("folder"))
    (base / "a.txt").write_text("a", encoding="utf-8")
    (base / "b.txt").write_text("b", encoding="utf-8")
    token = login("admin")

    res = client.post("/rename/a.txt", json={"name": "b.txt", "csrf_token": token},
                      headers=csrf_headers(token))

    assert res.status_code == 400
    assert (base / "b.txt").read_text(encoding="utf-8") == "b"
