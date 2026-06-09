"""
性能测试
"""

import unittest
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.merkle import MerkleTree
from src.crypto import Ed25519Signer, DomainSeparatedHash


class TestMerkleTreePerformance(unittest.TestCase):
    """默克尔树性能测试"""
    
    def test_append_performance(self):
        """测试追加性能"""
        tree = MerkleTree()
        num_entries = 10000
        
        start_time = time.time()
        for i in range(num_entries):
            tree.add_leaf(f"Log entry {i}".encode())
        elapsed = time.time() - start_time
        
        print(f"\n追加 {num_entries} 条目: {elapsed:.4f}秒")
        print(f"平均每条目: {elapsed/num_entries*1000:.4f}毫秒")
        
        self.assertEqual(tree.tree_size, num_entries)
    
    def test_inclusion_proof_performance(self):
        """测试包含证明生成性能"""
        tree = MerkleTree()
        num_entries = 10000
        
        for i in range(num_entries):
            tree.add_leaf(f"Entry {i}".encode())
        
        # 测试随机索引的证明生成
        import secrets
        indices = [secrets.randbelow(num_entries) for _ in range(100)]
        
        start_time = time.time()
        for idx in indices:
            proof = tree.get_inclusion_proof(idx)
        elapsed = time.time() - start_time
        
        print(f"\n生成 100 个包含证明 (树大小 {num_entries}): {elapsed:.4f}秒")
        print(f"平均每个证明: {elapsed/100*1000:.4f}毫秒")
    
    def test_inclusion_proof_verification_performance(self):
        """测试包含证明验证性能"""
        tree = MerkleTree()
        num_entries = 10000
        
        for i in range(num_entries):
            tree.add_leaf(f"Entry {i}".encode())
        
        # 生成证明
        import secrets
        indices = [secrets.randbelow(num_entries) for _ in range(100)]
        proofs = []
        for idx in indices:
            proof = tree.get_inclusion_proof(idx)
            proofs.append((proof, tree.root_hash))
        
        # 验证
        start_time = time.time()
        for proof, root in proofs:
            MerkleTree.verify_inclusion_proof(proof, root)
        elapsed = time.time() - start_time
        
        print(f"\n验证 100 个包含证明 (树大小 {num_entries}): {elapsed:.4f}秒")
        print(f"平均每个验证: {elapsed/100*1000:.4f}毫秒")
    
    def test_consistency_proof_performance(self):
        """测试一致性证明性能"""
        tree = MerkleTree()
        num_entries = 10000
        
        for i in range(num_entries):
            tree.add_leaf(f"Entry {i}".encode())
        
        # 测试多个大小的一致性证明
        sizes = [100, 1000, 5000, 9999]
        
        start_time = time.time()
        for size in sizes:
            proof = tree.get_consistency_proof(size)
            is_valid = MerkleTree.verify_consistency_proof(proof, tree.root_hash)
            self.assertTrue(is_valid)
        elapsed = time.time() - start_time
        
        print(f"\n生成并验证 4 个一致性证明 (树大小 {num_entries}): {elapsed:.4f}秒")
    
    def test_large_tree_performance(self):
        """测试大规模树性能"""
        tree = MerkleTree()
        num_entries = 100000
        
        print(f"\n构建包含 {num_entries} 个叶子的默克尔树...")
        
        # 构建树
        start_time = time.time()
        for i in range(num_entries):
            tree.add_leaf(f"Entry {i}".encode())
        build_time = time.time() - start_time
        
        print(f"构建时间: {build_time:.4f}秒")
        print(f"树深度: {tree._depth}")
        
        # 随机验证
        import secrets
        indices = [secrets.randbelow(num_entries) for _ in range(50)]
        
        start_time = time.time()
        for idx in indices:
            proof = tree.get_inclusion_proof(idx)
            MerkleTree.verify_inclusion_proof(proof, tree.root_hash)
        verify_time = time.time() - start_time
        
        print(f"50次随机验证时间: {verify_time:.4f}秒")
        print(f"通信开销: 约 {len(indices[0].proof_hashes) * 32} 字节/次验证")


class TestSignaturePerformance(unittest.TestCase):
    """签名性能测试"""
    
    def test_signing_performance(self):
        """测试签名性能"""
        signer = Ed25519Signer()
        
        tree_size = 10000
        root_hash = b'\x01' * 32
        timestamp = int(time.time())
        
        num_signatures = 1000
        
        start_time = time.time()
        for _ in range(num_signatures):
            signer.sign_sth(tree_size, root_hash, timestamp)
        elapsed = time.time() - start_time
        
        print(f"\n生成 {num_signatures} 个STH签名: {elapsed:.4f}秒")
        print(f"平均每个签名: {elapsed/num_signatures*1000:.4f}毫秒")
    
    def test_verification_performance(self):
        """测试验签性能"""
        signer = Ed25519Signer()
        
        tree_size = 10000
        root_hash = b'\x01' * 32
        timestamp = int(time.time())
        
        signature = signer.sign_sth(tree_size, root_hash, timestamp)
        verifier = Ed25519Verifier(signer.public_key_bytes)
        
        num_verifications = 1000
        
        start_time = time.time()
        for _ in range(num_verifications):
            verifier.verify_sth(tree_size, root_hash, timestamp, signature)
        elapsed = time.time() - start_time
        
        print(f"\n验证 {num_verifications} 个STH签名: {elapsed:.4f}秒")
        print(f"平均每次验证: {elapsed/num_verifications*1000:.4f}毫秒")


class TestHashPerformance(unittest.TestCase):
    """哈希性能测试"""
    
    def test_hash_throughput(self):
        """测试哈希吞吐量"""
        data = b"Test data for hashing" * 10
        
        num_hashes = 100000
        
        # 叶子哈希
        start_time = time.time()
        for _ in range(num_hashes):
            DomainSeparatedHash.hash_leaf(data)
        elapsed = time.time() - start_time
        
        print(f"\n生成 {num_hashes} 个叶子哈希: {elapsed:.4f}秒")
        print(f"吞吐量: {num_hashes/elapsed:.2f} 哈希/秒")
    
    def test_internal_hash_throughput(self):
        """测试内部节点哈希吞吐量"""
        left = b'\x01' * 32
        right = b'\x02' * 32
        
        num_hashes = 100000
        
        start_time = time.time()
        for _ in range(num_hashes):
            DomainSeparatedHash.hash_internal(left, right)
        elapsed = time.time() - start_time
        
        print(f"\n生成 {num_hashes} 个内部节点哈希: {elapsed:.4f}秒")
        print(f"吞吐量: {num_hashes/elapsed:.2f} 哈希/秒")


if __name__ == '__main__':
    # 运行性能测试
    print("=" * 60)
    print("性能测试结果")
    print("=" * 60)
    
    unittest.main(verbosity=2)
