# Legacy Code (Deprecated)

`웹서버 프로그램v4.py` is a monolithic v4-era prototype kept for historical reference only.

- **Not used at runtime** — the active implementation lives under `webshare_app/`.
- **Do not import** from application code; top-level wrappers (`server.py`, `config.py`, etc.) forward to `webshare_app/` instead.
- Safe to ignore when exploring the codebase with CodeGraph or grep.