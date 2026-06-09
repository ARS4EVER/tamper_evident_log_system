"""默克尔树操作辅助函数。

采用严格的 RFC 6962 标准重新实现，确保包含证明与一致性证明拓扑一致。
"""

from typing import List

from ..crypto import DomainSeparatedHash


def _largest_power_of_two_less_than(n: int) -> int:
    """返回小于 n 的最大 2 的幂。"""
    if n <= 1:
        return 1
    return 1 << ((n - 1).bit_length() - 1)


def compute_root_from_leaves(leaves: List[bytes]) -> bytes:
    """从叶子节点列表计算默克尔树根 (RFC 6962 标准)。"""
    if not leaves:
        raise ValueError("叶子列表不能为空")
    if len(leaves) == 1:
        return leaves[0]
    
    k = _largest_power_of_two_less_than(len(leaves))
    left_root = compute_root_from_leaves(leaves[:k])
    right_root = compute_root_from_leaves(leaves[k:])
    return DomainSeparatedHash.hash_internal(left_root, right_root)


def get_tree_depth(tree_size: int) -> int:
    """计算给定大小的树的深度。
    
    返回树的层级数（从0开始）。
    """
    if tree_size <= 1:
        return 0
    return (tree_size - 1).bit_length()


def find_first_diff_level(old_size: int, new_size: int) -> int:
    """找到旧树大小与新树大小的首个不同位所在的层级。"""
    xor = old_size ^ new_size
    if xor == 0:
        return 0
    return xor.bit_length() - 1


# ---------- 包含证明 ----------

def build_inclusion_proof(
    leaves: List[bytes],
    leaf_index: int,
) -> List[bytes]:
    """构建 RFC 6962 标准的包含证明。"""
    if leaf_index < 0 or leaf_index >= len(leaves):
        raise ValueError(f"无效的叶子索引: {leaf_index}")

    proof_hashes: List[bytes] = []

    def _build(sub_leaves: List[bytes], idx: int):
        if len(sub_leaves) == 1:
            return
        k = _largest_power_of_two_less_than(len(sub_leaves))
        if idx < k:
            proof_hashes.append(compute_root_from_leaves(sub_leaves[k:]))
            _build(sub_leaves[:k], idx)
        else:
            proof_hashes.append(compute_root_from_leaves(sub_leaves[:k]))
            _build(sub_leaves[k:], idx - k)

    _build(leaves, leaf_index)
    # 包含证明通常自底向上排列
    return proof_hashes[::-1]


def verify_inclusion_proof_with_hash(
    leaf_hash: bytes,
    proof_hashes: List[bytes],
    leaf_index: int,
    tree_size: int,
    root_hash: bytes,
) -> bool:
    """使用 RFC 6962 结构验证包含证明。"""
    if leaf_index < 0 or leaf_index >= tree_size:
        return False

    # 将证明倒序以方便自顶向下递归验证
    proof_iter = iter(proof_hashes[::-1])

    def _verify(index: int, size: int) -> bytes:
        if size == 1:
            return leaf_hash
        k = _largest_power_of_two_less_than(size)
        try:
            if index < k:
                right = next(proof_iter)
                left = _verify(index, k)
                return DomainSeparatedHash.hash_internal(left, right)
            else:
                left = next(proof_iter)
                right = _verify(index - k, size - k)
                return DomainSeparatedHash.hash_internal(left, right)
        except StopIteration:
            return b''

    computed_root = _verify(leaf_index, tree_size)
    return computed_root == root_hash


def verify_inclusion_proof_with_data(
    leaf_data: bytes,
    proof_hashes: List[bytes],
    leaf_index: int,
    tree_size: int,
    root_hash: bytes,
) -> bool:
    """使用原始叶子数据验证包含证明。"""
    current_hash = DomainSeparatedHash.hash_leaf(leaf_data)
    return verify_inclusion_proof_with_hash(
        current_hash, proof_hashes, leaf_index, tree_size, root_hash
    )


# ---------- 一致性证明 ----------

def build_consistency_proof(
    leaves: List[bytes],
    old_size: int,
    new_size: int,
) -> List[bytes]:
    """基于 RFC 6962 构建一致性证明。"""
    if old_size <= 0 or new_size <= 0:
        raise ValueError("树大小必须为正")
    if old_size > new_size:
        raise ValueError("旧树大小不能大于新树大小")
    if old_size == new_size:
        return []

    proof_hashes: List[bytes] = []
    _build_consistency_proof_rfc6962(leaves, old_size, new_size, proof_hashes)
    return proof_hashes


def _build_consistency_proof_rfc6962(
    leaves: List[bytes],
    m: int,
    n: int,
    proof: List[bytes],
) -> None:
    """RFC 6962 一致性证明生成算法。"""
    if m == n:
        return

    k = _largest_power_of_two_less_than(n)

    if m <= k:
        # 当 m <= k 时，需要证明的是左边的 k 个节点
        # 只有当 n > k 且 m != k 时才需要添加右边的证明
        if n > k and m != k:
            right_root = compute_root_from_leaves(leaves[k:n])
            proof.append(right_root)
        _build_consistency_proof_rfc6962(leaves[:k], m, k, proof)
    else:
        # 当 m > k 时，左边的 k 个节点是完整的子树
        # 需要将其根添加到证明中，然后处理右边的部分
        left_root = compute_root_from_leaves(leaves[:k])
        proof.append(left_root)
        _build_consistency_proof_rfc6962(leaves[k:n], m - k, n - k, proof)


def verify_consistency_proof_rfc6962(
    old_root: bytes,
    new_root: bytes,
    proof_hashes: List[bytes],
    m: int,
    n: int,
) -> bool:
    """使用 RFC 6962 算法验证一致性证明（无需访问叶子）。"""
    if m < 0 or n < 0:
        return False
    if m > n:
        return False
    if m == n:
        return old_root == new_root and len(proof_hashes) == 0
    if m == 0:
        return len(proof_hashes) == 0

    fn = n
    fm = m
    current = new_root
    i = len(proof_hashes) - 1

    while fm > 0:
        # 当 fn == fm 时，当前节点就是旧树根，直接返回
        if fn == fm:
            return i == -1 and current == old_root
            
        if fn % 2 == 1:
            if fm <= fn - 1:
                if i < 0:
                    return False
                current = DomainSeparatedHash.hash_internal(current, proof_hashes[i])
                i -= 1
            fn = fn // 2
            fm = fm // 2
        else:
            if fm > fn // 2:
                if i < 0:
                    return False
                current = DomainSeparatedHash.hash_internal(proof_hashes[i], current)
                i -= 1
                fm -= fn // 2
            fn = fn // 2

    return i == -1 and current == old_root


def verify_consistency_proof_by_recomputation(
    all_leaves: List[bytes],
    old_root: bytes,
    new_root: bytes,
    m: int,
    n: int,
) -> bool:
    """通过重计算验证一致性（有权访问叶子时使用）。"""
    if m < 0 or n < 0:
        return False
    if m > n:
        return False
    if n > len(all_leaves):
        return False

    if m == 0:
        return True

    old_leaves = all_leaves[:m]
    if compute_root_from_leaves(old_leaves) != old_root:
        return False

    new_leaves = all_leaves[:n]
    return compute_root_from_leaves(new_leaves) == new_root
