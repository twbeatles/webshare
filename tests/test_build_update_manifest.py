from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.build_update_manifest import build_manifest, main as build_manifest_main
from webshare_app.core.update_manifest import verify_release_manifest


def test_build_manifest(tmp_path: Path):
    private_key = Ed25519PrivateKey.generate()
    public_b64 = base64.b64encode(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode("ascii")

    artifact = tmp_path / "WebSharePro-v7.3.0.exe"
    artifact.write_bytes(b"dummy exe content for manifest build")

    manifest_dict = build_manifest(
        version="7.3.0",
        artifact=artifact,
        artifact_url="https://github.com/twbeatles/webshare/releases/download/v7.3.0/WebSharePro-v7.3.0.exe",
        private_key=private_key,
        expires_at=datetime.now(timezone.utc) + timedelta(days=365),
    )

    assert "payload" in manifest_dict
    assert "signature" in manifest_dict

    verified = verify_release_manifest(
        manifest_dict,
        public_key=public_b64,
        current_version="7.2.4",
    )
    assert verified.version == "7.3.0"
    assert verified.artifact_size == len(b"dummy exe content for manifest build")


def test_build_manifest_cli(tmp_path: Path, monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    private_b64 = base64.b64encode(
        private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    ).decode("ascii")
    public_b64 = base64.b64encode(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode("ascii")

    monkeypatch.setenv("TEST_UPDATE_PRIV_KEY", private_b64)

    artifact = tmp_path / "WebSharePro-v7.3.0.exe"
    artifact.write_bytes(b"cli test binary")

    out_file = tmp_path / "latest.json"

    exit_code = build_manifest_main(
        [
            "--version",
            "7.3.0",
            "--artifact",
            str(artifact),
            "--artifact-url",
            "https://github.com/twbeatles/webshare/releases/download/v7.3.0/WebSharePro-v7.3.0.exe",
            "--private-key-env",
            "TEST_UPDATE_PRIV_KEY",
            "--output",
            str(out_file),
        ]
    )
    assert exit_code == 0
    assert out_file.is_file()

    doc = json.loads(out_file.read_text(encoding="utf-8"))
    verified = verify_release_manifest(
        doc,
        public_key=public_b64,
        current_version="7.2.4",
    )
    assert verified.version == "7.3.0"
