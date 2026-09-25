"""Milestone B contract parity: Python reference vs Go port.

Golden vectors in tests/fixtures/go_migration/milestone_b/ were generated
from these same Python implementations. This suite locks the contract on the
Python side and cross-checks both directions through a Go probe binary
(go-core/cmd/testprobe, built once per session; skipped when no Go
toolchain is available).
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
VEC_DIR = REPO / "tests" / "fixtures" / "go_migration" / "milestone_b"
GO_DIR = REPO / "go-core"


def load(name):
    with open(VEC_DIR / name, encoding="utf-8") as f:
        return json.load(f)


def go_toolchain():
    override = os.environ.get("WEBSHARE_GO_BIN")
    if override and Path(override).is_file():
        return override
    found = shutil.which("go")
    if found:
        return found
    local = GO_DIR / ".tools" / "go" / "bin" / ("go.exe" if sys.platform == "win32" else "go")
    if local.is_file():
        return str(local)
    repo_tools = REPO / ".tools" / "go" / "bin" / ("go.exe" if sys.platform == "win32" else "go")
    if repo_tools.is_file():
        return str(repo_tools)
    return None


@pytest.fixture(scope="session")
def probe(tmp_path_factory):
    go = go_toolchain()
    if go is None:
        pytest.skip("Go toolchain unavailable for cross-backend probe")
    out = tmp_path_factory.mktemp("probe") / ("testprobe.exe" if sys.platform == "win32" else "testprobe")
    env = dict(os.environ)
    env["GOCACHE"] = str(tmp_path_factory.mktemp("gocache"))
    r = subprocess.run([go, "build", "-o", str(out), "./cmd/testprobe"],
                       cwd=str(GO_DIR), capture_output=True, text=True,
                       timeout=300, env=env)
    if r.returncode != 0 or not out.is_file():
        pytest.skip(f"testprobe build failed: {r.stderr[-500:]}")
    return str(out)


# --- password contract -------------------------------------------------

def test_password_vectors_against_python():
    from security.auth import verify_password

    vec = load("password_vectors.json")
    assert vec["cases"], "empty password vectors"
    for i, c in enumerate(vec["cases"]):
        assert verify_password(c["stored"], c["provided"]) is c["expect"], f"case {i}"


def test_password_python_reads_go_hash(probe):
    from werkzeug.security import check_password_hash

    h = subprocess.run([probe, "pwhash", "parity-secret-pw"],
                       capture_output=True, text=True, timeout=60).stdout.strip()
    assert h.startswith("pbkdf2:sha256:")
    assert check_password_hash(h, "parity-secret-pw")
    assert not check_password_hash(h, "parity-secret-pX")


def test_password_go_reads_python_hash(probe):
    vec = load("password_vectors.json")
    for i, c in enumerate(vec["cases"]):
        r = subprocess.run([probe, "pwverify", c["stored"], c["provided"]],
                           capture_output=True, timeout=120)
        assert (r.returncode == 0) is c["expect"], f"case {i}"


# --- session cookie contract --------------------------------------------

def _flask_serializer(secret):
    from itsdangerous import URLSafeTimedSerializer
    from flask.json.tag import TaggedJSONSerializer

    return URLSafeTimedSerializer(
        secret, salt="cookie-session", serializer=TaggedJSONSerializer(),
        signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1})


def test_session_vectors_against_python():
    from itsdangerous import BadSignature, SignatureExpired

    vec = load("session_vectors.json")
    for c in vec["cases"]:
        secret = c.get("secret", vec["secret"])
        s = _flask_serializer(secret)
        max_age = c.get("max_age", 31 * 24 * 3600)
        if c["expect"] == "valid":
            payload = s.loads(c["cookie"], max_age=max_age)
            for k, want in c["payload"].items():
                assert payload[k] == want, f"{c['name']}.{k}"
        elif c["expect"] == "expired":
            with pytest.raises(SignatureExpired):
                s.loads(c["cookie"], max_age=max_age)
        else:
            with pytest.raises(BadSignature):
                s.loads(c["cookie"], max_age=max_age)


def test_session_go_cookie_reads_in_python(probe):
    secret = "parity-session-secret"
    payload = {"logged_in": True, "role": "admin", "session_id": "cd" * 16,
               "language": "ko", "last_active": 1788000000.5}
    cookie = subprocess.run([probe, "sessign", secret, json.dumps(payload)],
                            capture_output=True, text=True, timeout=60).stdout.strip()
    got = _flask_serializer(secret).loads(cookie, max_age=31 * 24 * 3600)
    assert got["role"] == "admin" and got["logged_in"] is True


def test_session_python_cookie_reads_in_go(probe):
    vec = load("session_vectors.json")
    for c in vec["cases"]:
        secret = c.get("secret", vec["secret"])
        args = [probe, "sesverify", secret, c["cookie"]]
        if "max_age" in c:
            args.append(str(c["max_age"]))
        else:
            args.append(str(31 * 24 * 3600))
        r = subprocess.run(args, capture_output=True, text=True, timeout=60)
        if c["expect"] == "valid":
            assert r.returncode == 0, c["name"]
            assert json.loads(r.stdout)["role"] == c["payload"]["role"]
        elif c["expect"] == "expired":
            assert r.returncode == 2, c["name"]
        else:
            assert r.returncode == 3, c["name"]


# --- CSRF contract ------------------------------------------------------

def test_csrf_round_trip_through_session():
    from webshare_app.app.factory import create_app
    from security.csrf import generate_csrf_token, validate_csrf_token

    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "f" * 64
    with app.test_request_context("/", method="POST",
                                  headers={"X-CSRF-Token": "f" * 64}):
        from flask import session as flask_session

        flask_session["_csrf_token"] = "f" * 64
        assert generate_csrf_token() == "f" * 64
        assert validate_csrf_token() is True
    with app.test_request_context("/", method="POST"):
        from flask import session as flask_session

        flask_session["_csrf_token"] = "f" * 64
        assert validate_csrf_token() is False


# --- path / permission contract -----------------------------------------

def test_path_vectors_against_python(tmp_path):
    import sys as _sys

    from utils.request_policy import (
        build_path_capabilities, ensure_path_access, is_protected_system_path,
        normalize_relative_path, get_parent_relative_path,
    )
    from utils.file_utils import validate_path
    import config as config_mod

    vec = load("path_vectors.json")
    for i, c in enumerate(vec["normalize"]):
        assert normalize_relative_path(c["inp"]) == c["out"], f"normalize {i}"
    for i, c in enumerate(vec["protected"]):
        assert is_protected_system_path(c["inp"]) is c["expect"], f"protected {i}"
    for i, c in enumerate(vec["parent"]):
        assert get_parent_relative_path(c["inp"]) == c["out"], f"parent {i}"

    root = tmp_path / "shared"
    for d in ("a/b", "realdir", "docs/public", "private"):
        (root / d).mkdir(parents=True)
    current_platform = {"win32": "windows", "linux": "linux", "darwin": "darwin"}.get(
        _sys.platform, _sys.platform)
    for i, c in enumerate(vec["validate"]):
        if c.get("platform", "any") not in ("any", current_platform):
            continue
        rel = c["rel"].replace("$ROOT", str(root)).replace("$PARENT", str(tmp_path))
        ok, _, _ = validate_path(str(root), rel)
        assert ok is c["expect_valid"], f"validate {i}: {c['rel']}"

    old_perms = dict(config_mod.FOLDER_PERMISSIONS)
    old_upload = config_mod.conf.config.get("allow_guest_upload")
    try:
        config_mod.FOLDER_PERMISSIONS.clear()
        config_mod.FOLDER_PERMISSIONS.update(vec["permission_store"])
        from security.permissions import check_permission

        for i, c in enumerate(vec["permission_checks"]):
            assert check_permission(c["path"], c["user"], c["action"]) is c["expect"], \
                f"perm {i}"
        for i, c in enumerate(vec["access"]):
            ok, _, code = ensure_path_access(c["path"], c["action"], c["role"])
            assert (ok is c["expect_ok"]) and code == c["expect_code"], f"access {i}"
        for i, c in enumerate(vec["capabilities"]):
            config_mod.conf.config["allow_guest_upload"] = c["allow_guest_upload"]
            got = build_path_capabilities(c["path"], c["role"],
                                          is_dir=c["is_dir"], item_type=c["item_type"])
            assert got == c["expect"], f"cap {i}"
    finally:
        config_mod.FOLDER_PERMISSIONS.clear()
        config_mod.FOLDER_PERMISSIONS.update(old_perms)
        config_mod.conf.config["allow_guest_upload"] = old_upload


# --- IP policy contract --------------------------------------------------

def test_ip_vectors_against_python():
    from utils.file_utils import _extract_client_ip_from_xff
    from security.ip_blocker import check_ip_whitelist, record_login_attempt, check_ip_blocked
    import config as config_mod

    vec = load("ip_vectors.json")
    for i, c in enumerate(vec["xff_extract"]):
        assert _extract_client_ip_from_xff(c["xff"], c["hops"]) == c["out"], f"xff {i}"
    old_wl = config_mod.conf.config.get("ip_whitelist")
    try:
        for i, c in enumerate(vec["whitelist"]):
            config_mod.conf.config["ip_whitelist"] = c["whitelist"]
            assert check_ip_whitelist(c["ip"]) is c["expect"], f"wl {i}"
    finally:
        config_mod.conf.config["ip_whitelist"] = old_wl
    assert vec["limits"] == {"max_attempts": 5, "block_minutes": 15}

    ip = "203.0.113.99"
    for _ in range(5):
        record_login_attempt(ip, False)
    blocked, remaining = check_ip_blocked(ip)
    assert blocked and remaining > 0
    record_login_attempt(ip, True)
    assert check_ip_blocked(ip) == (False, 0)
