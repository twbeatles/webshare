# Legacy Code (Deprecated)

- `웹서버 프로그램v4.py` is a monolithic v4-era prototype kept for historical reference only.
- `server_controller.py` is the pre-migration `webshare_app/server/controller.py`
  (dead code: zero importers, superseded by `webshare_app/server/__init__.py`
  + `go_process.py`). Moved here during the Go migration (Milestone C).
- `templates_v72.py` is the pre-migration `routes/templates.py` (v7.2 embedded
  HTML: login/browse/share templates, ~216KB). Zero importers — the only
  reference was a `# ... (Removed)` comment in
  `webshare_app/routes/share_routes.py`; the Go core serves JSON for share
  flows instead of these templates. Moved here during the Go migration
  (Milestone F).

- **Not used at runtime** — the active implementation lives under `webshare_app/` (Python) and `go-core/` (Go).
- **Do not import** from application code; top-level wrappers (`server.py`, `config.py`, etc.) forward to `webshare_app/` instead.
- Safe to ignore when exploring the codebase with CodeGraph or grep.
