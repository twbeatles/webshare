"""Recent-file tracking helpers (per session/owner)."""

from __future__ import annotations
from datetime import datetime
from config import RECENT_FILES, recent_files_lock




def build_recent_owner_key(session_id: str = "", role: str = "guest", ip: str = "") -> str:
    owner_sid = str(session_id or "").strip()
    if owner_sid:
        return owner_sid
    return f"{role}:{ip}"




def add_recent_file(path: str, name: str, file_type: str = "file", owner_key: str = ""):
    """Add a recently accessed file entry for one session/owner."""
    if not owner_key:
        return

    with recent_files_lock:
        owner_entries = RECENT_FILES.setdefault(owner_key, [])

        for index, item in enumerate(owner_entries):
            if item.get("path") == path:
                owner_entries.pop(index)
                break

        owner_entries.insert(
            0,
            {
                "path": path,
                "name": name,
                "type": file_type,
                "accessed": datetime.now().isoformat(),
            },
        )

        while len(owner_entries) > 20:
            owner_entries.pop()




def get_recent_files(owner_key: str) -> list[dict]:
    with recent_files_lock:
        return list(RECENT_FILES.get(owner_key, [])[:20])

