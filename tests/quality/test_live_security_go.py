"""Live security boundaries on the REAL Go backend.

test_live_security_boundary.py drives the Python server only, which let a
Go-only gap through: guests could list, restore and empty the trash on the
default backend (audit ISSUE-001). These checks run the same admin-only
boundaries against the Go subprocess.
"""

import json

from live_harness import GUEST_PW, seed_files

_ADMIN_ONLY_GET = ("/trash/list", "/api/audit_log", "/share/list", "/versions/victim.txt")
_ADMIN_ONLY_POST = (
    ("/trash/restore", {"name": "x"}),
    ("/trash/empty", {}),
    ("/trash/cleanup", {}),
    ("/api/trash/cleanup", {}),
    ("/versions/restore", {"version": "x", "target": "victim.txt"}),
    ("/share/create", {"path": "victim.txt", "hours": 1}),
)


def test_go_guest_cannot_use_admin_endpoints(go_live_server):
    seed_files(go_live_server.shared, {"victim.txt": b"v" * 64})
    admin = go_live_server.admin_client()
    status, moved = admin.post_json("/trash", {"path": "victim.txt"})
    assert status == 200 and moved.get("success"), moved
    trash_dir = go_live_server.shared / ".webshare_trash"
    before = sorted(p.name for p in trash_dir.iterdir())
    assert before

    guest = go_live_server.client()
    guest.login(GUEST_PW)
    for path in _ADMIN_ONLY_GET:
        status, _, _ = guest._request("GET", path, headers={"X-Requested-With": "XMLHttpRequest"})
        assert status == 403, (path, status)
    for path, body in _ADMIN_ONLY_POST:
        status, _ = guest.post_json(path, body)
        assert status == 403, (path, status)

    assert sorted(p.name for p in trash_dir.iterdir()) == before
    meta = json.loads((go_live_server.shared / ".webshare_trash.json").read_text(encoding="utf-8"))
    assert set(meta["entries"]) == set(before)
