"""
审计专用默克尔树

在基础 MerkleTree 上增加批量证明验证与审计追踪功能。
"""

from typing import List, Tuple

from .core import MerkleTree
from .proofs import InclusionProof
from ..crypto import DomainSeparatedHash


class AuditMerkleTree(MerkleTree):
    """审计专用默克尔树。"""

    def batch_verify_inclusion_proofs(
        self,
        proofs: List[Tuple[InclusionProof, bytes]],
    ) -> List[bool]:
        """批量验证包含证明。"""
        results: List[bool] = []
        for proof, root_hash in proofs:
            results.append(self.verify_inclusion_proof(proof, root_hash))
        return results

    def audit_trace(self, leaf_index: int) -> List[Tuple[str, bytes]]:
        """生成审计追踪路径 (层级描述, 哈希值)。"""
        if leaf_index < 0 or leaf_index >= self._tree_size:
            raise ValueError(f"无效的叶子索引: {leaf_index}")

        trace: List[Tuple[str, bytes]] = []
        trace.append((f"Leaf[{leaf_index}]", self._leaves[leaf_index]))

        current_index = leaf_index
        level_nodes = self._leaves.copy()
        level = 0

        while len(level_nodes) > 1:
            is_left = (current_index % 2 == 0)
            if is_left:
                sibling_index = current_index + 1 if current_index + 1 < len(level_nodes) else current_index
                direction = "R"
            else:
                sibling_index = current_index - 1
                direction = "L"

            trace.append((f"Level[{level}] {direction}", level_nodes[sibling_index]))

            next_level = []
            for i in range(0, len(level_nodes), 2):
                if i + 1 < len(level_nodes):
                    left, right = level_nodes[i], level_nodes[i + 1]
                else:
                    left = right = level_nodes[i]
                next_level.append(DomainSeparatedHash.hash_internal(left, right))
            level_nodes = next_level
            current_index = current_index // 2
            level += 1

        trace.append(("Root", self._root))
        return trace
