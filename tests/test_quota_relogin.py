"""A new session from the same client cannot reset the daily download limit (audit ISSUE-008)."""

import time
from datetime import datetime
from pathlib import Path

from config import ACTIVE_SESSIONS, DOWNLOAD_TRACKER, conf, session_lock


def _use_session(client, sid):
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["role"] = "guest"
        sess["session_id"] = sid
        sess["last_active"] = time.time()
        sess["_csrf_token"] = "csrf-guest"
    with session_lock:
        ACTIVE_SESSIONS[sid] = {
            "ip": "127.0.0.1",
            "role": "guest",
            "login_time": datetime.now(),
            "last_active": datetime.now(),
        }


def test_relogin_does_not_reset_daily_download_limit(app, client):
    conf.config["daily_download_limit"] = 2
    Path(conf.get("folder"), "quota.txt").write_text("x", encoding="utf-8")

    codes = []
    for sid in ("sid-first", "sid-first", "sid-second"):
        _use_session(client, sid)
        codes.append(client.get("/download/quota.txt").status_code)

    assert codes == [200, 200, 429]


def test_download_charges_session_and_ip_keys(app, client):
    conf.config["daily_download_limit"] = 10
    Path(conf.get("folder"), "quota.txt").write_text("abc", encoding="utf-8")
    _use_session(client, "sid-charge")

    assert client.get("/download/quota.txt").status_code == 200

    assert DOWNLOAD_TRACKER["session:sid-charge"]["count"] == 1
    assert DOWNLOAD_TRACKER["ip:127.0.0.1"]["count"] == 1
