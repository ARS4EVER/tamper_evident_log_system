"""默克尔树核心实现。

支持动态追加叶子节点、包含证明/一致性证明的生成与验证。
"""

from typing import List, Optional

from .proofs import InclusionProof, ConsistencyProof
from ._tree_ops import (
    compute_root_from_leaves,
    build_inclusion_proof,
    build_consistency_proof,
    verify_inclusion_proof_with_data,
    verify_inclusion_proof_with_hash,
    verify_consistency_proof_rfc6962,
    verify_consistency_proof_by_recomputation,
    get_tree_depth,
)
from ..crypto import DomainSeparatedHash


class MerkleTree:
    """默克尔树实现。

    支持动态添加叶子，生成/验证包含证明和一致性证明。
    """

    def __init__(self):
        self._leaves: List[bytes] = []
        self._tree_size: int = 0
        self._depth: int = 0
        self._root: Optional[bytes] = None

    # ---------- 属性 ----------

    @property
    def tree_size(self) -> int:
        return self._tree_size

    @property
    def root_hash(self) -> Optional[bytes]:
        return self._root

    @property
    def leaves(self) -> List[bytes]:
        return self._leaves.copy()

    # ---------- 叶子操作 ----------

    def add_leaf(self, data: bytes) -> int:
        leaf_hash = DomainSeparatedHash.hash_leaf(data)
        return self.add_leaf_hash(leaf_hash)

    def add_leaf_hash(self, leaf_hash: bytes) -> int:
        if len(leaf_hash) != 32:
            raise ValueError("叶子哈希必须为 32 字节")
        self._leaves.append(leaf_hash)
        self._tree_size += 1
        self._recompute_root_and_depth()
        return self._tree_size - 1

    def _recompute_root_and_depth(self) -> None:
        if self._tree_size == 0:
            self._root = None
            self._depth = 0
            return
        self._root = compute_root_from_leaves(self._leaves)
        self._depth = get_tree_depth(self._tree_size)

    def get_leaf_hash(self, leaf_index: int) -> bytes:
        if leaf_index < 0 or leaf_index >= self._tree_size:
            raise ValueError(f"无效的叶子索引: {leaf_index}")
        return self._leaves[leaf_index]

    # ---------- 包含证明 ----------

    def get_inclusion_proof(self, leaf_index: int) -> InclusionProof:
        if leaf_index < 0 or leaf_index >= self._tree_size:
            raise ValueError(f"无效的叶子索引: {leaf_index}")
        if self._tree_size == 0:
            raise ValueError("树为空")

        proof_hashes = build_inclusion_proof(self._leaves, leaf_index)

        return InclusionProof(
            leaf_index=leaf_index,
            leaf_hash=self._leaves[leaf_index],
            proof_hashes=proof_hashes,
            tree_size=self._tree_size,
        )

    def verify_inclusion_proof(
        self, proof: InclusionProof, root_hash: bytes
    ) -> bool:
        """使用证明中的 leaf_hash 验证包含证明。"""
        return verify_inclusion_proof_with_hash(
            proof.leaf_hash,
            proof.proof_hashes,
            proof.leaf_index,
            root_hash,
        )

    @staticmethod
    def verify_inclusion_proof_with_data(
        leaf_data: bytes,
        proof: InclusionProof,
        root_hash: bytes,
    ) -> bool:
        """使用原始叶子数据验证包含证明。"""
        return verify_inclusion_proof_with_data(
            leaf_data,
            proof.proof_hashes,
            proof.leaf_index,
            proof.tree_size,
            root_hash,
        )

    # ---------- 一致性证明 ----------

    def get_consistency_proof(self, old_tree_size: int) -> ConsistencyProof:
        """生成一致性证明。

        生成从 old_tree_size 扩展到当前树大小的一致性证明。
        证明包含：旧树根哈希 + RFC 6962 格式的兄弟节点哈希列表。
        """
        if old_tree_size < 0 or old_tree_size > self._tree_size:
            raise ValueError(f"无效的旧树大小: {old_tree_size}")
        if self._tree_size == 0:
            raise ValueError("树为空")
        
        # 空树的一致性证明（RFC 6962允许）
        if old_tree_size == 0:
            return ConsistencyProof(
                old_tree_size=0,
                new_tree_size=self._tree_size,
                old_root_hash=b'',  # 空树没有根哈希
                proof_hashes=[]
            )

        old_leaves = self._leaves[:old_tree_size]
        old_root = compute_root_from_leaves(old_leaves)

        if old_tree_size == self._tree_size:
            return ConsistencyProof(
                old_tree_size=old_tree_size,
                old_root_hash=old_root,
                proof_hashes=[],
                new_tree_size=self._tree_size,
            )

        proof_hashes = build_consistency_proof(
            self._leaves, old_tree_size, self._tree_size
        )

        return ConsistencyProof(
            old_tree_size=old_tree_size,
            old_root_hash=old_root,
            proof_hashes=proof_hashes,
            new_tree_size=self._tree_size,
        )

    @staticmethod
    def verify_consistency_proof(
        proof: ConsistencyProof,
        new_root_hash: bytes,
        leaves: Optional[List[bytes]] = None,
    ) -> bool:
        """验证一致性证明。

        Args:
            proof: 一致性证明。
            new_root_hash: 声称的新树根哈希。
            leaves: 可选的叶子列表（用于完整重计算验证）。
                   如果为 None，则使用 RFC 6962 算法进行验证。
                   建议始终提供叶子以进行可靠的重计算验证。
        """
        if proof.old_tree_size < 0 or proof.new_tree_size < 0:
            return False

        if proof.old_tree_size > proof.new_tree_size:
            return False

        if proof.old_tree_size == proof.new_tree_size:
            return (
                proof.old_root_hash == new_root_hash
                and len(proof.proof_hashes) == 0
            )

        if leaves is not None:
            if proof.new_tree_size > len(leaves):
                return False
            return verify_consistency_proof_by_recomputation(
                leaves,
                proof.old_root_hash,
                new_root_hash,
                proof.old_tree_size,
                proof.new_tree_size,
            )

        # 如果没有叶子，使用 RFC 6962 验证（不太可靠，仅用于完整性）
        return verify_consistency_proof_rfc6962(
            proof.old_root_hash,
            new_root_hash,
            proof.proof_hashes,
            proof.old_tree_size,
            proof.new_tree_size,
        )

    def verify_consistency_proof_self(
        self, proof: ConsistencyProof, new_root_hash: bytes
    ) -> bool:
        """在 MerkleTree 实例上验证一致性证明（使用内部叶子重计算）。"""
        if proof.new_tree_size != self._tree_size:
            return False
        return MerkleTree.verify_consistency_proof(
            proof, new_root_hash, self._leaves
        )

    # ---------- 状态持久化 ----------

    def export_state(self) -> dict:
        return {
            "tree_size": self._tree_size,
            "leaves": [h.hex() for h in self._leaves],
            "root_hash": self._root.hex() if self._root else None,
        }

    @classmethod
    def load_state(cls, state: dict) -> "MerkleTree":
        tree = cls()
        for leaf_hex in state["leaves"]:
            tree.add_leaf_hash(bytes.fromhex(leaf_hex))
        return tree
