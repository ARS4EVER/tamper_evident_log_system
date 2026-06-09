"""
密钥管理模块

负责 Ed25519 签名密钥与 AES 加密密钥的生成、加载与持有。
"""

from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

from .signatures import Ed25519Signer
from .encryption import AESCipher


class KeyManager:
    """密钥管理器。"""

    def __init__(self):
        self._signing_key: Optional[Ed25519Signer] = None
        self._encryption_key: Optional[AESCipher] = None

    def generate_signing_key(self) -> Ed25519Signer:
        """生成新的 Ed25519 签名密钥对。"""
        self._signing_key = Ed25519Signer()
        return self._signing_key

    def set_signing_key(self, private_key_bytes: bytes) -> Ed25519Signer:
        """从私钥字节加载签名密钥。"""
        if not HAS_CRYPTOGRAPHY:
            raise ImportError("cryptography 库未安装")
        private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        self._signing_key = Ed25519Signer(private_key)
        return self._signing_key

    def get_signing_key(self) -> Optional[Ed25519Signer]:
        """获取签名器。"""
        return self._signing_key

    def set_encryption_key(self, key: bytes) -> AESCipher:
        """设置加密密钥。"""
        self._encryption_key = AESCipher(key)
        return self._encryption_key

    def generate_encryption_key(self) -> AESCipher:
        """生成新的 AES-256 加密密钥。"""
        self._encryption_key = AESCipher()
        return self._encryption_key

    def get_encryption_key(self) -> Optional[AESCipher]:
        """获取加密器。"""
        return self._encryption_key
