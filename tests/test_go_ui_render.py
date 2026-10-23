"""Go backend web UI shells rendered from the real templates (audit ISSUE-003)."""

import json
import re

from webshare_app.server.go_ui import CSRF_PLACEHOLDER, PATH_PLACEHOLDER, render_go_ui


def test_render_go_ui_writes_all_shells(tmp_path):
    written = render_go_ui(tmp_path)

    expected = {"manifest.json", "sw.js", "offline.html"}
    for lang in ("ko", "en"):
        expected |= {f"login_{lang}.html", f"login_{lang}_error.html"}
        expected |= {f"browse_{lang}_{v}.html" for v in ("admin", "guest_rw", "guest_ro")}
    assert set(written) == expected
    assert json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))["name"] == "WebShare Pro"


def test_browse_shell_has_placeholders_and_no_template_syntax(tmp_path):
    render_go_ui(tmp_path)
    admin = (tmp_path / "browse_ko_admin.html").read_text(encoding="utf-8")

    assert f'name="csrf-token" content="{CSRF_PLACEHOLDER}"' in admin
    assert f"window.CURRENT_PATH = {PATH_PLACEHOLDER};" in admin
    assert admin.count(PATH_PLACEHOLDER) == 1
    assert "window.ENABLE_API_LIST_RENDER = true" in admin
    assert "window.WS_HLS_ENABLED = false" in admin
    assert not re.search(r"\{\{|\{%", admin)
    # Go-supported admin tools stay, Python-only ones are left out.
    assert "openModal('trashModal')" in admin
    assert "loadActiveSessions(); closeDropdowns()" not in admin
    assert "openPermissionsModal(); closeDropdowns()" not in admin
    assert "handleCtx('encrypt')" not in admin


def test_guest_shells_differ_by_upload_permission(tmp_path):
    render_go_ui(tmp_path)
    guest_rw = (tmp_path / "browse_en_guest_rw.html").read_text(encoding="utf-8")
    guest_ro = (tmp_path / "browse_en_guest_ro.html").read_text(encoding="utf-8")

    assert 'id="uploadBtn"' in guest_rw
    assert 'id="uploadBtn"' not in guest_ro
    assert 'id="adminDropdown"' not in guest_rw


def test_python_rendering_is_unchanged_without_go_shell(client, login):
    login("admin")
    page = client.get("/browse/").get_data(as_text=True)

    assert "window.CURRENT_PATH = '';" in page
    assert "__WS_" not in page
    assert "loadActiveSessions(); closeDropdowns()" in page
