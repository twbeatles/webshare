"""
WebShare Pro - Crypto
AES 파일 암호화/복호화
"""

import os
import struct

from utils.log_manager import logger

MAGIC = b"WSE2"
VERSION = 1
HEADER_STRUCT = struct.Struct(">4sBBBI")
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
DEFAULT_ITERATIONS = 200000
IO_CHUNK_SIZE = 1024 * 1024


def _derive_key(password: str, salt: bytes, iterations: int):
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file_aes(file_path: str, password: str) -> tuple:
    """
    AES-GCM(v2)으로 파일 암호화 (스트리밍).

    Returns:
        (성공여부, 결과 파일 경로 또는 에러 메시지)
    """
    try:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        return (False, "cryptography 라이브러리가 필요합니다. pip install cryptography")

    if not os.path.isfile(file_path):
        return (False, "파일을 찾을 수 없습니다.")

    try:
        salt = os.urandom(SALT_LEN)
        nonce = os.urandom(NONCE_LEN)
        key = _derive_key(password, salt, DEFAULT_ITERATIONS)

        out_path = file_path + ".enc"
        temp_out_path = out_path + ".tmp"
        header = HEADER_STRUCT.pack(MAGIC, VERSION, SALT_LEN, NONCE_LEN, DEFAULT_ITERATIONS) + salt + nonce

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(file_path, "rb") as src, open(temp_out_path, "wb") as dst:
            dst.write(header)
            while True:
                chunk = src.read(IO_CHUNK_SIZE)
                if not chunk:
                    break
                encrypted = encryptor.update(chunk)
                if encrypted:
                    dst.write(encrypted)
            encryptor.finalize()
            dst.write(encryptor.tag)

        if os.path.exists(out_path):
            os.remove(out_path)
        os.replace(temp_out_path, out_path)
        os.remove(file_path)
        logger.add(f"파일 암호화 완료: {os.path.basename(file_path)}")
        return (True, out_path)
    except Exception as exc:
        logger.add(f"파일 암호화 실패: {exc}", "ERROR")
        try:
            if "temp_out_path" in locals() and os.path.exists(temp_out_path):
                os.remove(temp_out_path)
        except Exception:
            pass
        return (False, "암호화 처리 중 오류가 발생했습니다.")


def _decrypt_file_v2(file_path: str, password: str) -> tuple:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    total_size = os.path.getsize(file_path)
    temp_out_path = ""
    try:
        with open(file_path, "rb") as src:
            fixed = src.read(HEADER_STRUCT.size)
            if len(fixed) != HEADER_STRUCT.size:
                return (False, "지원하지 않는 암호화 포맷입니다.")

            magic, version, salt_len, nonce_len, iterations = HEADER_STRUCT.unpack(fixed)
            if magic != MAGIC:
                return (False, "지원하지 않는 암호화 포맷입니다.")
            if version != VERSION:
                return (False, f"지원하지 않는 암호화 버전입니다: {version}")
            if salt_len <= 0 or nonce_len <= 0 or iterations <= 0:
                return (False, "암호화 헤더가 손상되었습니다.")

            salt = src.read(salt_len)
            nonce = src.read(nonce_len)
            if len(salt) != salt_len or len(nonce) != nonce_len:
                return (False, "암호화 헤더가 손상되었습니다.")

            header_len = HEADER_STRUCT.size + salt_len + nonce_len
            if total_size < header_len + TAG_LEN:
                return (False, "암호화 데이터가 손상되었습니다.")

            ciphertext_len = total_size - header_len - TAG_LEN
            src.seek(header_len + ciphertext_len)
            tag = src.read(TAG_LEN)
            if len(tag) != TAG_LEN:
                return (False, "암호화 데이터가 손상되었습니다.")

            key = _derive_key(password, salt, iterations)
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=default_backend(),
            ).decryptor()

            out_path = file_path[:-4]
            temp_out_path = out_path + ".tmp"

            src.seek(header_len)
            remaining = ciphertext_len
            with open(temp_out_path, "wb") as dst:
                while remaining > 0:
                    to_read = min(IO_CHUNK_SIZE, remaining)
                    chunk = src.read(to_read)
                    if not chunk:
                        return (False, "암호화 데이터가 손상되었습니다.")
                    remaining -= len(chunk)
                    plain = decryptor.update(chunk)
                    if plain:
                        dst.write(plain)
                decryptor.finalize()

        os.replace(temp_out_path, out_path)
        os.remove(file_path)
        logger.add(f"파일 복호화 완료(v2): {os.path.basename(out_path)}")
        return (True, out_path)
    except InvalidTag:
        return (False, "잘못된 비밀번호이거나 파일이 손상되었습니다.")
    except Exception as exc:
        logger.add(f"파일 복호화(v2) 실패: {exc}", "ERROR")
        return (False, "복호화 처리 중 오류가 발생했습니다.")
    finally:
        if temp_out_path and os.path.exists(temp_out_path):
            try:
                os.remove(temp_out_path)
            except Exception:
                pass


def _decrypt_file_legacy_cbc(file_path: str, password: str) -> tuple:
    """v1 레거시(CBC) 포맷 복호화 호환."""
    try:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        return (False, "cryptography 라이브러리가 필요합니다. pip install cryptography")

    try:
        with open(file_path, "rb") as handle:
            data = handle.read()

        if len(data) < 32:
            return (False, "암호화된 데이터 형식이 올바르지 않습니다.")

        salt = data[:16]
        iv = data[16:32]
        ciphertext = data[32:]

        key = _derive_key(password, salt, 100000)
        decryptor = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend(),
        ).decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        if not plaintext:
            return (False, "잘못된 비밀번호이거나 파일이 손상되었습니다.")

        padding_length = plaintext[-1]
        if padding_length < 1 or padding_length > 16:
            return (False, "잘못된 비밀번호이거나 파일이 손상되었습니다.")
        if plaintext[-padding_length:] != bytes([padding_length]) * padding_length:
            return (False, "잘못된 비밀번호이거나 파일이 손상되었습니다.")
        plaintext = plaintext[:-padding_length]

        out_path = file_path[:-4]
        temp_out_path = out_path + ".tmp"
        with open(temp_out_path, "wb") as handle:
            handle.write(plaintext)
        os.replace(temp_out_path, out_path)
        os.remove(file_path)
        logger.add(f"파일 복호화 완료(legacy): {os.path.basename(out_path)}")
        return (True, out_path)
    except Exception as exc:
        logger.add(f"파일 복호화(legacy) 실패: {exc}", "ERROR")
        return (False, "잘못된 비밀번호이거나 파일이 손상되었습니다.")


def decrypt_file_aes(file_path: str, password: str) -> tuple:
    """
    암호화 파일 복호화.
    - v2 헤더 감지 시 AES-GCM 스트리밍 복호화
    - 헤더 미존재 시 legacy CBC 포맷 복호화
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher  # noqa: F401
    except ImportError:
        return (False, "cryptography 라이브러리가 필요합니다. pip install cryptography")

    if not file_path.endswith(".enc"):
        return (False, "암호화된 파일(.enc)이 아닙니다.")

    if not os.path.isfile(file_path):
        return (False, "파일을 찾을 수 없습니다.")

    try:
        with open(file_path, "rb") as handle:
            prefix = handle.read(len(MAGIC))
    except Exception:
        return (False, "파일을 읽을 수 없습니다.")

    if prefix == MAGIC:
        return _decrypt_file_v2(file_path, password)
    return _decrypt_file_legacy_cbc(file_path, password)
