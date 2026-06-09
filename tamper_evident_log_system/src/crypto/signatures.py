"""
Ed25519 签名与验签模块

基于 RFC 8032,提供确定性签名与恒定时间执行,抵抗侧信道攻击。
"""

from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class Ed25519Signer:
    """Ed25519 签名器。"""

    def __init__(self, private_key: Optional["Ed25519PrivateKey"] = None):
        if private_key is None:
            self._private_key = Ed25519PrivateKey.generate()
        else:
            self._private_key = private_key
        self._public_key = self._private_key.public_key()

    @property
    def public_key_bytes(self) -> bytes:
        """获取 32 字节公钥。"""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def private_key_bytes(self) -> bytes:
        """获取 32 字节私钥。"""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def sign(self, message: bytes) -> bytes:
        """对消息生成 Ed25519 签名。"""
        return self._private_key.sign(message)

    def sign_sth(self, tree_size: int, root_hash: bytes, timestamp: int) -> bytes:
        """对签名树根 (STH) 生成签名。"""
        sth_data = self._serialize_sth(tree_size, root_hash, timestamp)
        return self.sign(sth_data)

    @staticmethod
    def _serialize_sth(tree_size: int, root_hash: bytes, timestamp: int) -> bytes:
        """序列化 STH 数据。"""
        sth_bytes = b'STH_v1'
        sth_bytes += tree_size.to_bytes(8, 'big')
        sth_bytes += root_hash
        sth_bytes += timestamp.to_bytes(8, 'big')
        return sth_bytes

    def verify(self, message: bytes, signature: bytes) -> bool:
        """验签 (本地公钥验证,主要用于自检)。"""
        try:
            self._public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False


class Ed25519Verifier:
    """Ed25519 验签器 (使用外部公钥)。"""

    def __init__(self, public_key: bytes):
        if not HAS_CRYPTOGRAPHY:
            raise ImportError("cryptography 库未安装")
        self._public_key = Ed25519PublicKey.from_public_bytes(public_key)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """验签。"""
        try:
            self._public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def verify_sth(self, tree_size: int, root_hash: bytes, timestamp: int, signature: bytes) -> bool:
        """验签 STH。"""
        sth_data = Ed25519Signer._serialize_sth(tree_size, root_hash, timestamp)
        return self.verify(sth_data, signature)
