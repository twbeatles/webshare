"""
WebShare Pro - Crypto
AES 파일 암호화/복호화
"""

import os
from ..utils.log_manager import logger


def encrypt_file_aes(file_path: str, password: str) -> tuple:
    """
    AES-256으로 파일 암호화
    
    Args:
        file_path: 암호화할 파일 경로
        password: 암호화 비밀번호
        
    Returns:
        (성공여부, 결과 파일 경로 또는 에러 메시지)
    """
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        return (False, "cryptography 라이브러리가 필요합니다. pip install cryptography")
    
    try:
        # 랜덤 salt와 IV 생성
        salt = os.urandom(16)
        iv = os.urandom(16)
        
        # 비밀번호에서 키 유도
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # 암호화
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # 파일 읽기
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        # PKCS7 패딩
        block_size = 16
        padding_length = block_size - (len(plaintext) % block_size)
        plaintext += bytes([padding_length]) * padding_length
        
        # 암호화
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # 암호화된 파일 저장 (salt + iv + ciphertext)
        enc_path = file_path + '.enc'
        with open(enc_path, 'wb') as f:
            f.write(salt + iv + ciphertext)
        
        # 원본 삭제
        os.remove(file_path)
        
        logger.add(f"파일 암호화 완료: {os.path.basename(file_path)}")
        return (True, enc_path)
        
    except Exception as e:
        logger.add(f"파일 암호화 실패: {e}", "ERROR")
        return (False, str(e))


def decrypt_file_aes(file_path: str, password: str) -> tuple:
    """
    AES-256으로 암호화된 파일 복호화
    
    Args:
        file_path: 복호화할 .enc 파일 경로
        password: 복호화 비밀번호
        
    Returns:
        (성공여부, 결과 파일 경로 또는 에러 메시지)
    """
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        return (False, "cryptography 라이브러리가 필요합니다. pip install cryptography")
    
    if not file_path.endswith('.enc'):
        return (False, "암호화된 파일(.enc)이 아닙니다.")
    
    try:
        # 암호화된 파일 읽기
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # salt, iv, ciphertext 분리
        salt = data[:16]
        iv = data[16:32]
        ciphertext = data[32:]
        
        # 비밀번호에서 키 유도
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # 복호화
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # PKCS7 패딩 검증 및 제거
        padding_length = plaintext[-1]
        
        # 패딩 값 유효성 검사
        if padding_length < 1 or padding_length > 16:
            return (False, "잘못된 비밀번호이거나 파일이 손상되었습니다.")
        
        # 패딩 바이트가 모두 동일한지 확인
        if plaintext[-padding_length:] != bytes([padding_length]) * padding_length:
            return (False, "잘못된 비밀번호이거나 파일이 손상되었습니다.")
        
        plaintext = plaintext[:-padding_length]
        
        # 복호화된 파일 저장
        dec_path = file_path[:-4]  # .enc 제거
        with open(dec_path, 'wb') as f:
            f.write(plaintext)
        
        # 암호화 파일 삭제
        os.remove(file_path)
        
        logger.add(f"파일 복호화 완료: {os.path.basename(dec_path)}")
        return (True, dec_path)
        
    except Exception as e:
        logger.add(f"파일 복호화 실패: {e}", "ERROR")
        return (False, "비밀번호가 올바르지 않거나 파일이 손상되었습니다.")
