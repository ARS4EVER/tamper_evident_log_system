"""
域隔离 SHA-256 哈希实现

为叶子节点与内部节点使用不同的前缀,防御第二原像攻击 (CVE-2012-2459)。
"""

import hashlib


# 域隔离前缀常量
LEAF_PREFIX = b'\x00'
INTERNAL_PREFIX = b'\x01'


class DomainSeparatedHash:
    """带域隔离的 SHA-256 哈希实现。"""

    HASH_OUTPUT_SIZE = 32  # SHA-256 输出长度

    @staticmethod
    def hash_leaf(data: bytes) -> bytes:
        """计算叶子节点哈希 (前缀 0x00)。"""
        return hashlib.sha256(LEAF_PREFIX + data).digest()

    @staticmethod
    def hash_internal(left_hash: bytes, right_hash: bytes) -> bytes:
        """计算内部节点哈希 (前缀 0x01)。"""
        return hashlib.sha256(INTERNAL_PREFIX + left_hash + right_hash).digest()

    @staticmethod
    def hash_bytes(data: bytes) -> bytes:
        """计算通用字节数据的哈希 (不带前缀,用于内部计算)。"""
        return hashlib.sha256(data).digest()
