import os
from pathlib import Path

import pytest

from config import conf
from features.crypto import decrypt_file_aes, encrypt_file_aes


def _build_legacy_cbc_file(path: Path, password: str, plaintext: bytes):
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    salt = os.urandom(16)
    iv = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode("utf-8"))

    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len]) * pad_len
    encryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend(),
    ).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    path.write_bytes(salt + iv + ciphertext)


def test_crypto_v2_encrypt_decrypt_roundtrip(client):
    pytest.importorskip("cryptography")
    base = Path(conf.get("folder"))
    original = base / "secret.txt"
    original.write_bytes(b"hello-v2")

    ok, enc_path = encrypt_file_aes(str(original), "pw")
    assert ok is True
    assert Path(enc_path).exists()
    assert original.exists() is False

    ok2, dec_path = decrypt_file_aes(enc_path, "pw")
    assert ok2 is True
    assert Path(dec_path).exists()
    assert Path(dec_path).read_bytes() == b"hello-v2"


def test_crypto_legacy_cbc_decrypt_supported(client):
    pytest.importorskip("cryptography")
    base = Path(conf.get("folder"))
    legacy_path = base / "legacy.txt.enc"
    _build_legacy_cbc_file(legacy_path, "legacy_pw", b"legacy-data")

    ok, dec_path = decrypt_file_aes(str(legacy_path), "legacy_pw")
    assert ok is True
    assert Path(dec_path).read_bytes() == b"legacy-data"


def test_docker_assets_exist_and_entrypoint_declared():
    root = Path(__file__).resolve().parents[1]
    dockerfile = root / "Dockerfile"
    compose = root / "docker-compose.yml"
    entrypoint = root / "docker_entrypoint.py"

    assert dockerfile.exists()
    assert compose.exists()
    assert entrypoint.exists()

    content = dockerfile.read_text(encoding="utf-8")
    assert 'CMD ["python", "docker_entrypoint.py"]' in content

