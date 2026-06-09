"""
签名树根 (Signed Tree Head, STH) 数据结构

STH 用于对外发布当前默克尔树的根哈希、树大小与时间戳,并附上 Ed25519 签名。
"""

from dataclasses import dataclass


@dataclass
class SignedTreeHead:
    """签名树根。"""

    tree_size: int
    root_hash: bytes
    timestamp: int
    signature: bytes

    def to_bytes(self) -> bytes:
        """序列化为字节串。"""
        data = b'STH_v1'
        data += self.tree_size.to_bytes(8, 'big')
        data += self.root_hash
        data += self.timestamp.to_bytes(8, 'big')
        data += self.signature
        return data

    def serialize_for_signing(self) -> bytes:
        """序列化为用于签名的数据（不含签名字段）。"""
        data = b'STH_v1'
        data += self.tree_size.to_bytes(8, 'big')
        data += self.root_hash
        data += self.timestamp.to_bytes(8, 'big')
        return data

    @classmethod
    def from_bytes(cls, data: bytes) -> "SignedTreeHead":
        """从字节串反序列化。"""
        # 修复核心点：'STH_v1' 的长度是 6，不是 7
        if data[:6] != b'STH_v1':
            raise ValueError("无效的 STH 格式")
        tree_size = int.from_bytes(data[6:14], 'big')
        root_hash = data[14:46]
        timestamp = int.from_bytes(data[46:54], 'big')
        signature = data[54:]
        return cls(tree_size, root_hash, timestamp, signature)