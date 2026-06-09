"""
默克尔证明模块

提供包含证明 (Inclusion Proof) 与一致性证明 (Consistency Proof) 的数据结构及
序列化/反序列化逻辑。
"""

from dataclasses import dataclass
from typing import List


@dataclass
class MerkleProof:
    """默克尔证明基类。"""
    pass


@dataclass
class InclusionProof(MerkleProof):
    """包含证明 - 证明指定叶子节点属于默克尔树。"""

    leaf_index: int
    leaf_hash: bytes
    proof_hashes: List[bytes]
    tree_size: int

    def to_bytes(self) -> bytes:
        """序列化为字节串。"""
        data = b'INC_v1'
        data += self.leaf_index.to_bytes(8, 'big')
        data += self.leaf_hash
        data += len(self.proof_hashes).to_bytes(4, 'big')
        for h in self.proof_hashes:
            data += h
        data += self.tree_size.to_bytes(8, 'big')
        return data

    @classmethod
    def from_bytes(cls, data: bytes) -> "InclusionProof":
        """从字节串反序列化。"""
        if data[:6] != b'INC_v1':
            raise ValueError("无效的包含证明格式")
        pos = 6
        leaf_index = int.from_bytes(data[pos:pos + 8], 'big')
        pos += 8
        leaf_hash = data[pos:pos + 32]
        pos += 32
        num_hashes = int.from_bytes(data[pos:pos + 4], 'big')
        pos += 4
        proof_hashes = []
        for _ in range(num_hashes):
            proof_hashes.append(data[pos:pos + 32])
            pos += 32
        tree_size = int.from_bytes(data[pos:pos + 8], 'big')
        return cls(leaf_index, leaf_hash, proof_hashes, tree_size)


@dataclass
class ConsistencyProof(MerkleProof):
    """一致性证明 - 证明新树包含旧树的所有节点。"""

    old_tree_size: int
    old_root_hash: bytes
    proof_hashes: List[bytes]
    new_tree_size: int

    def to_bytes(self) -> bytes:
        """序列化为字节串。"""
        data = b'CON_v1'
        data += self.old_tree_size.to_bytes(8, 'big')
        data += self.old_root_hash
        data += len(self.proof_hashes).to_bytes(4, 'big')
        for h in self.proof_hashes:
            data += h
        data += self.new_tree_size.to_bytes(8, 'big')
        return data

    @classmethod
    def from_bytes(cls, data: bytes) -> "ConsistencyProof":
        """从字节串反序列化。"""
        if data[:6] != b'CON_v1':
            raise ValueError("无效的一致性证明格式")
        pos = 6
        old_tree_size = int.from_bytes(data[pos:pos + 8], 'big')
        pos += 8
        old_root_hash = data[pos:pos + 32]
        pos += 32
        num_hashes = int.from_bytes(data[pos:pos + 4], 'big')
        pos += 4
        proof_hashes = []
        for _ in range(num_hashes):
            proof_hashes.append(data[pos:pos + 32])
            pos += 32
        new_tree_size = int.from_bytes(data[pos:pos + 8], 'big')
        return cls(old_tree_size, old_root_hash, proof_hashes, new_tree_size)
