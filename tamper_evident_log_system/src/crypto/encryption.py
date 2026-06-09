"""
AES-256-GCM 加密模块

提供带认证的加密/解密功能。
"""

import secrets
from typing import Optional, Tuple

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class AESCipher:
    """AES-256-GCM 加密器。"""

    KEY_SIZE = 32      # AES-256
    NONCE_SIZE = 12    # GCM 推荐 12 字节 nonce

    def __init__(self, key: Optional[bytes] = None):
        if key is None:
            self._key = AESGCM.generate_key(bit_length=256)
        else:
            if len(key) != self.KEY_SIZE:
                raise ValueError(f"密钥长度必须为 {self.KEY_SIZE} 字节")
            self._key = key
        self._aesgcm = AESGCM(self._key)

    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """加密数据,返回 (nonce, 密文+认证标签)。"""
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)
        return nonce, ciphertext

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
        """解密数据,认证标签验证失败将抛出异常。"""
        return self._aesgcm.decrypt(nonce, ciphertext, aad)

    @staticmethod
    def generate_key() -> bytes:
        """生成随机 AES-256 密钥。"""
        return secrets.token_bytes(AESCipher.KEY_SIZE)
