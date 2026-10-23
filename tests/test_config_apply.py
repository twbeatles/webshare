"""Saved settings reach the running server (audit ISSUE-007)."""

import webshare_app.server as server_pkg


class _FakeGo:
    def __init__(self, restart):
        self._restart = restart
        self.reload_calls = 0

    def is_alive(self):
        return True

    def reload_config(self):
        self.reload_calls += 1
        return self._restart


def test_apply_config_changes_reloads_running_go(monkeypatch):
    fake = _FakeGo(["port"])
    monkeypatch.setattr(server_pkg, "_go_process", fake)

    result = server_pkg.apply_config_changes()

    assert fake.reload_calls == 1
    assert result == {"running": True, "applied": True, "restart_required": ["port"]}


def test_apply_config_changes_reports_failed_go_reload(monkeypatch):
    monkeypatch.setattr(server_pkg, "_go_process", _FakeGo(None))

    result = server_pkg.apply_config_changes()

    assert result["running"] is True
    assert result["applied"] is False


def test_apply_config_changes_without_server(monkeypatch):
    monkeypatch.setattr(server_pkg, "_go_process", None)
    monkeypatch.setattr(server_pkg, "server_thread", None)

    assert server_pkg.apply_config_changes() == {"running": False, "applied": True, "restart_required": []}
