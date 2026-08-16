from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from scripts.apply_update import main as apply_update_main


def test_apply_update_main_success(tmp_path: Path, monkeypatch):
    target = tmp_path / "WebSharePro.exe"
    target.write_bytes(b"old binary content")

    new_content = b"new upgraded binary content"
    staged = tmp_path / "staged.exe"
    staged.write_bytes(new_content)

    backup = tmp_path / "WebSharePro.exe.v7.2.4.bak"
    result_file = tmp_path / "last-update-result.json"

    sha256 = hashlib.sha256(new_content).hexdigest()

    # Mock wait_for_parent to return immediately
    monkeypatch.setattr("scripts.apply_update._wait_for_parent", lambda _pid, timeout=30.0: None)
    # Mock subprocess.run for smoke check
    import subprocess
    class MockCompletedProcess:
        returncode = 0
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: MockCompletedProcess())

    exit_code = apply_update_main(
        [
            "--target",
            str(target),
            "--staged",
            str(staged),
            "--backup",
            str(backup),
            "--parent-pid",
            "999999",
            "--expected-sha256",
            sha256,
            "--expected-size",
            str(len(new_content)),
            "--result-file",
            str(result_file),
        ]
    )

    assert exit_code == 0
    assert result_file.is_file()
    result_data = json.loads(result_file.read_text(encoding="utf-8"))
    assert result_data["status"] == "applied"
    assert target.read_bytes() == new_content
    assert backup.read_bytes() == b"old binary content"

