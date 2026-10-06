"""Twin live-server fixtures must start from clean guard state.

Regression test for order-dependent twin failures: failed logins, quota
usage and auth-attempt records left by earlier tests must not leak into the
module-scoped live-server fixtures (which bypass the `app` fixture).
"""

from config import (
    DOWNLOAD_TRACKER,
    LOGIN_ATTEMPTS,
    conf,
    download_tracker_lock,
    login_attempts_lock,
)
from conftest import reset_live_guard_state
from security.ip_blocker import record_login_attempt
from webshare_app.features import webdav_server
from webshare_app.services import share_service


def test_reset_live_guard_state_clears_polluted_guards(tmp_path, monkeypatch):
    # Point runtime state at tmp: record_login_attempt persists a block to
    # the configured folder, which must never be the developer checkout.
    import webshare_app.core.config.manager as _config_manager

    monkeypatch.setattr(
        _config_manager, "CONFIG_FILE", str(tmp_path / "webshare_config.json")
    )
    saved_folder = conf.get("folder")
    conf.set("folder", str(tmp_path / "shared"))
    try:
        for _ in range(8):
            record_login_attempt("127.0.0.1", success=False)
        with login_attempts_lock:
            assert "127.0.0.1" in LOGIN_ATTEMPTS
        with download_tracker_lock:
            DOWNLOAD_TRACKER["ip:127.0.0.1"] = {
                "count": 5,
                "bytes": 5,
                "date": "2000-01-01",
            }
        share_service.record_share_password_attempt("127.0.0.1", "tok", success=False)
        assert ("127.0.0.1", "tok") in share_service._share_password_attempts
        webdav_server._record_auth_attempt("127.0.0.1", success=False)
        assert "127.0.0.1" in webdav_server._webdav_auth_attempts

        reset_live_guard_state()

        with login_attempts_lock:
            assert LOGIN_ATTEMPTS == {}
        with download_tracker_lock:
            assert DOWNLOAD_TRACKER == {}
        assert share_service._share_password_attempts == {}
        assert webdav_server._webdav_auth_attempts == {}
    finally:
        conf.set("folder", saved_folder)
