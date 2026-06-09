"""诊断脚本 - 检查序列化和证明长度"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.merkle import MerkleTree, InclusionProof, ConsistencyProof
from src.crypto import SignedTreeHead


print("=" * 60)
print("问题 1: 序列化前缀长度检查")
print("=" * 60)
print(f"len(b'INC_v1') = {len(b'INC_v1')}")
print(f"len(b'CON_v1') = {len(b'CON_v1')}")
print(f"len(b'STH_v1') = {len(b'STH_v1')}")
print()

sth = SignedTreeHead(
    tree_size=1000,
    root_hash=b'\xAB' * 32,
    timestamp=1234567890,
    signature=b'\xCD' * 64,
)
serialized = sth.to_bytes()
print(f"STH serialized: {serialized[:10]!r}... len={len(serialized)}")
print(f"First 7 bytes: {serialized[:7]!r}")
print(f"Compare to b'STH_v1': {b'STH_v1'!r}")
print(f"serialized[:7] == b'STH_v1'? {serialized[:7] == b'STH_v1'}")
print(f"serialized[:6] == b'STH_v1'? {serialized[:6] == b'STH_v1'}")
print()

print("=" * 60)
print("问题 2: 包含证明的哈希数")
print("=" * 60)
tree = MerkleTree()
for i in range(100):
    tree.add_leaf(f"Log entry {i}".encode())

print(f"tree_size = {tree.tree_size}")
print(f"_depth = {tree._depth}")
print(f"_depth + 1 = {tree._depth + 1}")

proof = tree.get_inclusion_proof(0)
print(f"proof.proof_hashes length = {len(proof.proof_hashes)}")
print(f"Expected (depth+1) = {tree._depth + 1}")
print()

for leaf_index in [0, 42, 99]:
    p = tree.get_inclusion_proof(leaf_index)
    valid = MerkleTree.verify_inclusion_proof_with_data(
        f"Log entry {leaf_index}".encode(), p, tree.root_hash
    )
    print(f"  leaf {leaf_index}: proof_hashes={len(p.proof_hashes)}, valid={valid}")

print()
print("=" * 60)
print("问题 3: 一致性证明")
print("=" * 60)
for old_size in [1, 10, 50, 75, 99]:
    p = tree.get_consistency_proof(old_size)
    ok = MerkleTree.verify_consistency_proof(p, tree.root_hash)
    print(f"  old_size={old_size}: proof_hashes={len(p.proof_hashes)}, valid={ok}")

print()
print("=" * 60)
print("手动验证一致性证明 (old=50, new=100)")
print("=" * 60)
old_tree = MerkleTree()
for i in range(50):
    old_tree.add_leaf(f"Log entry {i}".encode())
print(f"old_tree root: {old_tree.root_hash.hex()[:16]}...")
print(f"new_tree root: {tree.root_hash.hex()[:16]}...")

proof = tree.get_consistency_proof(50)
print(f"ConsistencyProof old_root_hash: {proof.old_root_hash.hex()[:16]}...")
print(f"Matches old_tree root? {proof.old_root_hash == old_tree.root_hash}")

# 手动验证逻辑
current = proof.old_root_hash
for h in proof.proof_hashes:
    from src.crypto import DomainSeparatedHash
    current = DomainSeparatedHash.hash_internal(current, h)
print(f"Manual compute result: {current.hex()[:16]}...")
print(f"new_tree root:           {tree.root_hash.hex()[:16]}...")
print(f"Match? {current == tree.root_hash}")

print()
print("=" * 60)
print("用更简单方法测试一致性证明算法")
print("=" * 60)
for old_size in [1, 10, 50, 75, 99]:
    m = old_size
    n = tree.tree_size
    print(f"\nold={m}, new={n}")
    
    # 简单的自底向上方法
    # 找到从 m-1 到根的路径，收集兄弟
    proof_hashes = []
    idx = m - 1  # 旧树最后一个叶子的索引
    
    # 获取旧树的每层节点
    old_leaves = tree._leaves[:m]
    old_levels = [old_leaves]
    current_level = old_leaves[:]
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                left, right = current_level[i], current_level[i + 1]
            else:
                left = right = current_level[i]
            from src.crypto import DomainSeparatedHash
            next_level.append(DomainSeparatedHash.hash_internal(left, right))
        old_levels.append(next_level)
        current_level = next_level
    
    print(f"  old_levels: {[len(l) for l in old_levels]}")
    
    # 获取新树的每层
    new_levels = [tree._leaves[:]]
    current_level = tree._leaves[:]
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                left, right = current_level[i], current_level[i + 1]
            else:
                left = right = current_level[i]
            from src.crypto import DomainSeparatedHash
            next_level.append(DomainSeparatedHash.hash_internal(left, right))
        new_levels.append(next_level)
        current_level = next_level
    
    print(f"  new_levels: {[len(l) for l in new_levels]}")
    print(f"  old root: {old_levels[-1][0].hex()[:8]}")
    print(f"  new root: {new_levels[-1][0].hex()[:8]}")
