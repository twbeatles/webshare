"""Windows login autostart registration (audit §5 Confirmed Gap)."""

import os

import pytest

from webshare_app.core import autostart


class _FakeKey:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeWinreg:
    HKEY_CURRENT_USER = "HKCU"
    KEY_READ = 1
    KEY_SET_VALUE = 2
    REG_SZ = 1

    def __init__(self):
        self.values = {}

    def OpenKey(self, root, path, reserved, access):
        assert (root, path) == ("HKCU", autostart.RUN_KEY)
        return _FakeKey()

    def CreateKeyEx(self, root, path, reserved, access):
        assert (root, path) == ("HKCU", autostart.RUN_KEY)
        return _FakeKey()

    def QueryValueEx(self, key, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        return self.values[name], self.REG_SZ

    def SetValueEx(self, key, name, reserved, kind, value):
        self.values[name] = value

    def DeleteValue(self, key, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        del self.values[name]


@pytest.fixture
def fake_registry(monkeypatch):
    reg = _FakeWinreg()
    monkeypatch.setattr(autostart, "_winreg", lambda: reg)
    monkeypatch.setattr(autostart, "is_supported", lambda: True)
    return reg


def test_enable_registers_command_with_workdir(fake_registry, tmp_path):
    ok, error = autostart.set_enabled(True, workdir=str(tmp_path))

    assert ok, error
    command = fake_registry.values[autostart.VALUE_NAME]
    assert "--workdir" in command
    assert str(tmp_path) in command
    assert autostart.is_enabled() is True


def test_disable_removes_entry_and_is_idempotent(fake_registry, tmp_path):
    autostart.set_enabled(True, workdir=str(tmp_path))

    assert autostart.set_enabled(False) == (True, "")
    assert autostart.VALUE_NAME not in fake_registry.values
    assert autostart.set_enabled(False) == (True, "")
    assert autostart.is_enabled() is False


def test_unsupported_platform_reports_error(monkeypatch):
    monkeypatch.setattr(autostart, "is_supported", lambda: False)

    ok, error = autostart.set_enabled(True)

    assert ok is False
    assert error


def test_main_applies_workdir_before_config(monkeypatch, tmp_path):
    import main

    monkeypatch.chdir(tmp_path.parent)  # restored after the test
    main._apply_workdir_arg(["--workdir", str(tmp_path)])

    assert os.path.samefile(os.getcwd(), tmp_path)
