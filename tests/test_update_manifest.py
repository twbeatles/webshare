from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from webshare_app.core.update_manifest import (
    NoUpdateAvailableError,
    canonical_manifest_payload,
    is_newer_version,
    verify_release_manifest,
)


@pytest.fixture
def keypair() -> tuple[str, str]:
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
    return private_b64, public_b64


def test_is_newer_version():
    assert is_newer_version("7.3.0", "7.2.4")
    assert is_newer_version("7.2.5", "7.2.4")
    assert is_newer_version("8.0.0", "7.2.4")
    assert not is_newer_version("7.2.4", "7.2.4")
    assert not is_newer_version("7.2.3", "7.2.4")
    assert not is_newer_version("7.1.9", "7.2.4")


def test_verify_release_manifest_valid(keypair: tuple[str, str]):
    private_b64, public_b64 = keypair
    private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))

    payload = {
        "version": "7.3.0",
        "artifact_url": "https://github.com/twbeatles/webshare/releases/download/v7.3.0/WebSharePro-v7.3.0.exe",
        "sha256": "a" * 64,
        "size": 1024,
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).replace(microsecond=0).isoformat(),
    }
    signature = base64.b64encode(
        private_key.sign(canonical_manifest_payload(payload))
    ).decode("ascii")

    document = {"payload": payload, "signature": signature}
    manifest = verify_release_manifest(
        document,
        public_key=public_b64,
        current_version="7.2.4",
    )

    assert manifest.version == "7.3.0"
    assert manifest.artifact_url.startswith("https://")
    assert manifest.artifact_sha256 == "a" * 64
    assert manifest.artifact_size == 1024


def test_verify_release_manifest_tampered_signature(keypair: tuple[str, str]):
    _, public_b64 = keypair
    other_private_key = Ed25519PrivateKey.generate()

    payload = {
        "version": "7.3.0",
        "artifact_url": "https://github.com/twbeatles/webshare/releases/download/v7.3.0/WebSharePro-v7.3.0.exe",
        "sha256": "a" * 64,
        "size": 1024,
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    }
    invalid_signature = base64.b64encode(
        other_private_key.sign(canonical_manifest_payload(payload))
    ).decode("ascii")

    document = {"payload": payload, "signature": invalid_signature}
    with pytest.raises(ValueError, match="Manifest signature verification failed"):
        verify_release_manifest(
            document,
            public_key=public_b64,
            current_version="7.2.4",
        )


def test_verify_release_manifest_not_newer(keypair: tuple[str, str]):
    private_b64, public_b64 = keypair
    private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))

    payload = {
        "version": "7.2.4",
        "artifact_url": "https://github.com/twbeatles/webshare/releases/download/v7.2.4/WebSharePro-v7.2.4.exe",
        "sha256": "a" * 64,
        "size": 1024,
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    }
    signature = base64.b64encode(
        private_key.sign(canonical_manifest_payload(payload))
    ).decode("ascii")

    document = {"payload": payload, "signature": signature}
    with pytest.raises(NoUpdateAvailableError):
        verify_release_manifest(
            document,
            public_key=public_b64,
            current_version="7.2.4",
        )


def test_verify_release_manifest_expired(keypair: tuple[str, str]):
    private_b64, public_b64 = keypair
    private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))

    payload = {
        "version": "7.3.0",
        "artifact_url": "https://github.com/twbeatles/webshare/releases/download/v7.3.0/WebSharePro-v7.3.0.exe",
        "sha256": "a" * 64,
        "size": 1024,
        "expires_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
    }
    signature = base64.b64encode(
        private_key.sign(canonical_manifest_payload(payload))
    ).decode("ascii")

    document = {"payload": payload, "signature": signature}
    with pytest.raises(ValueError, match="Manifest is expired"):
        verify_release_manifest(
            document,
            public_key=public_b64,
            current_version="7.2.4",
        )


def test_verify_release_manifest_insecure_url(keypair: tuple[str, str]):
    private_b64, public_b64 = keypair
    private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))

    payload = {
        "version": "7.3.0",
        "artifact_url": "http://insecure.example.com/WebSharePro.exe",
        "sha256": "a" * 64,
        "size": 1024,
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    }
    signature = base64.b64encode(
        private_key.sign(canonical_manifest_payload(payload))
    ).decode("ascii")

    document = {"payload": payload, "signature": signature}
    with pytest.raises(ValueError, match="Manifest artifact_url must be HTTPS"):
        verify_release_manifest(
            document,
            public_key=public_b64,
            current_version="7.2.4",
        )
