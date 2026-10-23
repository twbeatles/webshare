"""Render the full web UI as static shells for the Go backend (audit ISSUE-003).

The Go core cannot run the Jinja templates, so the launcher renders them once
per start with ``go_shell=True`` into a cache directory that it hands to the
Go child (``--ui-dir``) together with the static assets (``--static-dir``).
Request-specific values stay as placeholders the Go core substitutes:

* ``__WS_CSRF__``        session CSRF token (meta tag and hidden form fields)
* ``__WS_PATH_JSON__``   current folder as a JS string literal

File rows, breadcrumbs, the parent row and the folder ZIP link are built in the
browser from ``/api/list`` (``ENABLE_API_LIST_RENDER``); admin tools that only
the Python backend implements are left out of the shell.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

CSRF_PLACEHOLDER = "__WS_CSRF__"
PATH_PLACEHOLDER = "__WS_PATH_JSON__"

LANGUAGES = ("ko", "en")
# (file suffix, role, can_modify)
SHELL_VARIANTS = (
    ("admin", "admin", True),
    ("guest_rw", "guest", True),
    ("guest_ro", "guest", False),
)


def asset_root() -> Path:
    """Directory holding ``templates/`` and ``static/`` (source or bundle)."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path.cwd()))
    return Path(__file__).resolve().parents[2]


def _environment(templates_dir: Path):
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.globals["csrf_token"] = lambda: CSRF_PLACEHOLDER
    return env


def render_go_ui(out_dir: str | os.PathLike, templates_dir: str | os.PathLike | None = None) -> list[str]:
    """Render login and browse shells into out_dir; returns written file names.

    Files: ``login_<lang>.html``, ``login_<lang>_error.html`` and
    ``browse_<lang>_<variant>.html`` for every language and shell variant,
    plus the PWA ``manifest.json``, ``sw.js`` and ``offline.html``.
    Writes go through a temp file + replace so a running Go child never reads
    a half-written shell.
    """
    from i18n import get_all_translations

    templates = Path(templates_dir) if templates_dir else asset_root() / "templates"
    env = _environment(templates)
    template = env.get_template("index.html")
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    def _write(name: str, html: str):
        temp = target / f".{name}.tmp"
        temp.write_text(html, encoding="utf-8")
        os.replace(temp, target / name)
        written.append(name)

    for lang in LANGUAGES:
        translations = get_all_translations(lang)
        common = {
            "t": translations,
            "translations_json": json.dumps(translations, ensure_ascii=False),
            "current_lang": lang,
            "user_api_enabled": False,
            "login_mode": "password",
            "go_shell": True,
        }
        _write(f"login_{lang}.html", template.render(logged_in=False, error=None, **common))
        _write(
            f"login_{lang}_error.html",
            template.render(logged_in=False, error=translations.get("invalid_password", "Invalid password"), **common),
        )
        for suffix, role, can_modify in SHELL_VARIANTS:
            html = template.render(
                logged_in=True,
                items=[],
                current_path="",
                breadcrumbs=[],
                list_page=1,
                list_page_size=200,
                list_total_count=0,
                list_total_pages=1,
                list_has_next=False,
                list_has_prev=False,
                list_sort={"by": "name", "order": "asc"},
                list_query="",
                current_capabilities={},
                role=role,
                can_modify=can_modify,
                **common,
            )
            _write(f"browse_{lang}_{suffix}.html", html)

    from webshare_app.routes.pwa_routes import MANIFEST, OFFLINE_HTML, service_worker_script

    _write("manifest.json", json.dumps(MANIFEST, ensure_ascii=False))
    _write("sw.js", service_worker_script())
    _write("offline.html", OFFLINE_HTML)
    return written
