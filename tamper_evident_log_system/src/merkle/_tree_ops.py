"""默克尔树操作辅助函数。

提供默克尔树的核心哈希计算和证明生成算法。
"""

from typing import List

from ..crypto import DomainSeparatedHash


def compute_root_from_leaves(leaves: List[bytes]) -> bytes:
    """从叶子节点列表计算默克尔树根。

    使用"复制最后一个节点"策略：如果某层节点数为奇数，
    最后一个节点与自身配对进行哈希。

    Args:
        leaves: 叶子哈希列表 (不能为空)。

    Returns:
        根哈希值 (32 字节)。
    """
    if not leaves:
        raise ValueError("叶子列表不能为空")

    current = leaves.copy()
    while len(current) > 1:
        next_level: List[bytes] = []
        for i in range(0, len(current), 2):
            if i + 1 < len(current):
                left = current[i]
                right = current[i + 1]
            else:
                left = right = current[i]
            next_level.append(DomainSeparatedHash.hash_internal(left, right))
        current = next_level
    return current[0]


def build_level_from_leaves(leaves: List[bytes], target_level: int) -> List[bytes]:
    """从叶子节点构建指定层级的节点列表。

    Args:
        leaves: 叶子哈希列表。
        target_level: 目标层级 (0 = 叶子层)。

    Returns:
        指定层级的节点哈希列表。
    """
    if target_level == 0:
        return leaves.copy()

    current = leaves.copy()
    for _ in range(target_level):
        next_level: List[bytes] = []
        for i in range(0, len(current), 2):
            if i + 1 < len(current):
                left, right = current[i], current[i + 1]
            else:
                left = right = current[i]
            next_level.append(DomainSeparatedHash.hash_internal(left, right))
        current = next_level
    return current


def get_tree_depth(tree_size: int) -> int:
    """计算给定大小的树的深度。
    
    返回树的层级数（从0开始）。
    例如：1个叶子返回0（只有根），2个叶子返回1，100个叶子返回7。
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
    """构建包含证明。

    Args:
        leaves: 所有叶子的哈希列表。
        leaf_index: 要证明的叶子的索引。

    Returns:
        证明哈希列表 (从叶子层向上的兄弟节点)。
    """
    if leaf_index < 0 or leaf_index >= len(leaves):
        raise ValueError(f"无效的叶子索引: {leaf_index}")

    proof_hashes: List[bytes] = []
    current_index = leaf_index
    level_nodes = leaves.copy()

    while len(level_nodes) > 1:
        is_left = current_index % 2 == 0
        if is_left:
            sibling_index = current_index + 1
            if sibling_index < len(level_nodes):
                proof_hashes.append(level_nodes[sibling_index])
            else:
                proof_hashes.append(level_nodes[current_index])
        else:
            sibling_index = current_index - 1
            proof_hashes.append(level_nodes[sibling_index])

        next_level: List[bytes] = []
        for i in range(0, len(level_nodes), 2):
            if i + 1 < len(level_nodes):
                left, right = level_nodes[i], level_nodes[i + 1]
            else:
                left = right = level_nodes[i]
            next_level.append(DomainSeparatedHash.hash_internal(left, right))
        level_nodes = next_level
        current_index //= 2

    return proof_hashes


def verify_inclusion_proof_with_data(
    leaf_data: bytes,
    proof_hashes: List[bytes],
    leaf_index: int,
    tree_size: int,
    root_hash: bytes,
) -> bool:
    """使用原始叶子数据验证包含证明。"""
    if leaf_index < 0 or leaf_index >= tree_size:
        return False

    current_hash = DomainSeparatedHash.hash_leaf(leaf_data)
    current_index = leaf_index
    for sibling_hash in proof_hashes:
        if current_index % 2 == 0:
            current_hash = DomainSeparatedHash.hash_internal(current_hash, sibling_hash)
        else:
            current_hash = DomainSeparatedHash.hash_internal(sibling_hash, current_hash)
        current_index //= 2
    return current_hash == root_hash


def verify_inclusion_proof_with_hash(
    leaf_hash: bytes,
    proof_hashes: List[bytes],
    leaf_index: int,
    root_hash: bytes,
) -> bool:
    """使用叶子哈希验证包含证明（不重新哈希叶子数据）。"""
    current_hash = leaf_hash
    current_index = leaf_index
    for sibling_hash in proof_hashes:
        if current_index % 2 == 0:
            current_hash = DomainSeparatedHash.hash_internal(current_hash, sibling_hash)
        else:
            current_hash = DomainSeparatedHash.hash_internal(sibling_hash, current_hash)
        current_index //= 2
    return current_hash == root_hash


# ---------- 一致性证明 ----------

def _largest_power_of_two_less_than(n: int) -> int:
    """返回小于 n 的最大 2 的幂。"""
    if n <= 1:
        return 1
    exponent = (n - 1).bit_length() - 1
    return 1 << exponent


def build_consistency_proof(
    leaves: List[bytes],
    old_size: int,
    new_size: int,
) -> List[bytes]:
    """基于 RFC 6962 构建一致性证明。

    构建从 old_size 叶子树扩展到 new_size 叶子树的一致性证明。

    Args:
        leaves: 所有叶子哈希列表。
        old_size: 旧树大小。
        new_size: 新树大小。

    Returns:
        证明哈希列表。
    """
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
    """使用 RFC 6962 算法验证一致性证明（无需访问叶子）。

    Args:
        old_root: 声称的旧树根哈希。
        new_root: 声称的新树根哈希。
        proof_hashes: 证明哈希列表。
        m: 旧树大小。
        n: 新树大小。

    Returns:
        证明是否有效。
    """
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
            # fn 是奇数：树结构为 [左子树(k), 右子树(n-k)]
            # current = Hash(left, right)
            # 如果 fm <= fn-1，旧树在前 fn-1 个节点中
            # 我们需要从 current 中剥离右子树，得到左子树
            if fm <= fn - 1:
                if i < 0:
                    return False
                # current = Hash(left, right), right = proof_hashes[i]
                # 我们需要计算 left = Hash(left)，但由于哈希不可逆
                # 根据 RFC 6962，这里应该是 current = Hash(current, proof_hashes[i])
                current = DomainSeparatedHash.hash_internal(current, proof_hashes[i])
                i -= 1
            fn = fn // 2
            fm = fm // 2
        else:
            # fn 是偶数：树结构为 [左子树(k), 右子树(k)]
            if fm > fn // 2:
                if i < 0:
                    return False
                # 旧树跨越左右子树，需要保留左子树的根
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
    """通过重计算验证一致性（有权访问叶子时使用）。

    直接重新计算 HASH(leaves[0:m]) 和 HASH(leaves[0:n]) 并与声称值比较。
    简单可靠，适合审计节点使用。

    Args:
        all_leaves: 所有叶子的哈希列表。
        old_root: 声称的旧树根。
        new_root: 声称的新树根。
        m: 旧树大小。
        n: 新树大小。

    Returns:
        如果新旧根与叶子一致返回 True。
    """
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
