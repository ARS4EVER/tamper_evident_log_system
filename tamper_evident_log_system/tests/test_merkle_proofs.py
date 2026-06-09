"""
默克尔树证明测试
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.merkle import MerkleTree, AuditMerkleTree, InclusionProof, ConsistencyProof
from src.crypto import DomainSeparatedHash


class TestMerkleTree(unittest.TestCase):
    """测试默克尔树"""
    
    def test_empty_tree(self):
        """测试空树"""
        tree = MerkleTree()
        
        self.assertEqual(tree.tree_size, 0)
        self.assertIsNone(tree.root_hash)
    
    def test_add_single_leaf(self):
        """测试添加单个叶子"""
        tree = MerkleTree()
        data = b"First leaf"
        
        index = tree.add_leaf(data)
        
        self.assertEqual(index, 0)
        self.assertEqual(tree.tree_size, 1)
        self.assertIsNotNone(tree.root_hash)
        self.assertEqual(len(tree.root_hash), 32)
    
    def test_add_multiple_leaves(self):
        """测试添加多个叶子"""
        tree = MerkleTree()
        
        for i in range(10):
            data = f"Leaf {i}".encode()
            index = tree.add_leaf(data)
            self.assertEqual(index, i)
        
        self.assertEqual(tree.tree_size, 10)
    
    def test_root_hash_consistency(self):
        """测试根哈希一致性"""
        tree1 = MerkleTree()
        tree2 = MerkleTree()
        
        data_list = [f"Data {i}".encode() for i in range(100)]
        
        for data in data_list:
            tree1.add_leaf(data)
        
        for data in data_list:
            tree2.add_leaf(data)
        
        self.assertEqual(tree1.root_hash, tree2.root_hash)
    
    def test_odd_leaf_padding(self):
        """测试奇数叶子节点填充"""
        tree = MerkleTree()
        
        # 添加3个叶子 (奇数)
        for i in range(3):
            tree.add_leaf(f"Leaf {i}".encode())
        
        self.assertEqual(tree.tree_size, 3)
        self.assertIsNotNone(tree.root_hash)
    
    def test_tree_depth(self):
        """测试树深度计算"""
        tree = MerkleTree()
        
        # 1 leaf: depth 0
        tree.add_leaf(b"1")
        self.assertEqual(tree._depth, 0)
        
        # 2-3 leaves: depth 1
        tree.add_leaf(b"2")
        self.assertEqual(tree._depth, 1)
        
        # 4-7 leaves: depth 2
        tree.add_leaf(b"3")
        tree.add_leaf(b"4")
        self.assertEqual(tree._depth, 2)
        
        # 8-15 leaves: depth 3
        for i in range(4, 8):
            tree.add_leaf(str(i).encode())
        self.assertEqual(tree._depth, 3)


class TestInclusionProof(unittest.TestCase):
    """测试包含证明"""
    
    def setUp(self):
        """设置测试树"""
        self.tree = MerkleTree()
        self.test_data = [f"Log entry {i}".encode() for i in range(100)]
        for data in self.test_data:
            self.tree.add_leaf(data)
    
    def test_proof_generation(self):
        """测试证明生成"""
        proof = self.tree.get_inclusion_proof(0)
        
        self.assertEqual(proof.leaf_index, 0)
        self.assertEqual(len(proof.proof_hashes), self.tree._depth)
        self.assertEqual(proof.tree_size, 100)
    
    def test_proof_verification(self):
        """测试证明验证"""
        leaf_index = 42
        leaf_data = self.test_data[leaf_index]
        
        proof = self.tree.get_inclusion_proof(leaf_index)
        
        # 使用原始数据验证
        is_valid = MerkleTree.verify_inclusion_proof_with_data(
            leaf_data, proof, self.tree.root_hash
        )
        
        self.assertTrue(is_valid)
    
    def test_proof_verification_wrong_data(self):
        """测试错误数据被拒绝"""
        leaf_index = 42
        wrong_data = b"Tampered data"
        
        proof = self.tree.get_inclusion_proof(leaf_index)
        
        is_valid = MerkleTree.verify_inclusion_proof_with_data(
            wrong_data, proof, self.tree.root_hash
        )
        
        self.assertFalse(is_valid)
    
    def test_proof_verification_wrong_root(self):
        """测试错误根哈希被拒绝"""
        leaf_index = 42
        leaf_data = self.test_data[leaf_index]
        
        proof = self.tree.get_inclusion_proof(leaf_index)
        
        # 使用不同的根哈希
        wrong_root = b'\xFF' * 32
        
        is_valid = MerkleTree.verify_inclusion_proof_with_data(
            leaf_data, proof, wrong_root
        )
        
        self.assertFalse(is_valid)
    
    def test_proof_serialization(self):
        """测试证明序列化"""
        leaf_index = 50
        proof = self.tree.get_inclusion_proof(leaf_index)
        
        # 序列化
        data = proof.to_bytes()
        
        # 反序列化
        proof2 = InclusionProof.from_bytes(data)
        
        self.assertEqual(proof.leaf_index, proof2.leaf_index)
        self.assertEqual(proof.leaf_hash, proof2.leaf_hash)
        self.assertEqual(proof.proof_hashes, proof2.proof_hashes)
        self.assertEqual(proof.tree_size, proof2.tree_size)
    
    def test_all_leaves_verification(self):
        """测试所有叶子验证"""
        for i in range(self.tree.tree_size):
            proof = self.tree.get_inclusion_proof(i)
            
            is_valid = MerkleTree.verify_inclusion_proof_with_data(
                self.test_data[i], proof, self.tree.root_hash
            )
            
            self.assertTrue(is_valid, f"验证失败: 索引 {i}")


class TestConsistencyProof(unittest.TestCase):
    """测试一致性证明"""
    
    def setUp(self):
        """设置测试树"""
        self.tree = MerkleTree()
        self.test_data = [f"Log entry {i}".encode() for i in range(100)]
        for data in self.test_data:
            self.tree.add_leaf(data)
    
    def test_same_size_proof(self):
        """测试相同大小的一致性证明"""
        proof = self.tree.get_consistency_proof(100)
        
        self.assertEqual(proof.old_tree_size, 100)
        self.assertEqual(proof.new_tree_size, 100)
        self.assertEqual(len(proof.proof_hashes), 0)
    
    def test_proof_verification_same_size(self):
        """测试相同大小证明验证"""
        proof = self.tree.get_consistency_proof(100)
        
        is_valid = MerkleTree.verify_consistency_proof(proof, self.tree.root_hash)
        
        self.assertTrue(is_valid)
    
    def test_partial_tree_proof(self):
        """测试部分树的一致性证明"""
        old_size = 50
        proof = self.tree.get_consistency_proof(old_size)
        
        self.assertEqual(proof.old_tree_size, old_size)
        self.assertEqual(proof.new_tree_size, 100)
        
        # 验证一致性（使用叶子进行重计算验证）
        is_valid = MerkleTree.verify_consistency_proof(proof, self.tree.root_hash, self.tree.leaves)
        
        self.assertTrue(is_valid)
    
    def test_proof_verification_wrong_root(self):
        """测试错误根哈希被拒绝"""
        old_size = 50
        proof = self.tree.get_consistency_proof(old_size)
        
        wrong_root = b'\xFF' * 32
        
        is_valid = MerkleTree.verify_consistency_proof(proof, wrong_root, self.tree.leaves)
        
        self.assertFalse(is_valid)
    
    def test_proof_serialization(self):
        """测试证明序列化"""
        old_size = 50
        proof = self.tree.get_consistency_proof(old_size)
        
        # 序列化
        data = proof.to_bytes()
        
        # 反序列化
        proof2 = ConsistencyProof.from_bytes(data)
        
        self.assertEqual(proof.old_tree_size, proof2.old_tree_size)
        self.assertEqual(proof.old_root_hash, proof2.old_root_hash)
        self.assertEqual(proof.proof_hashes, proof2.proof_hashes)
        self.assertEqual(proof.new_tree_size, proof2.new_tree_size)
    
    def test_multiple_size_proofs(self):
        """测试多个不同大小的一致性证明"""
        sizes = [1, 10, 50, 75, 99]
        
        for old_size in sizes:
            proof = self.tree.get_consistency_proof(old_size)
            is_valid = MerkleTree.verify_consistency_proof(proof, self.tree.root_hash, self.tree.leaves)
            self.assertTrue(is_valid, f"大小 {old_size} 验证失败")


class TestAuditMerkleTree(unittest.TestCase):
    """测试审计专用默克尔树"""
    
    def test_audit_trace(self):
        """测试审计追踪"""
        tree = AuditMerkleTree()
        
        for i in range(10):
            tree.add_leaf(f"Entry {i}".encode())
        
        trace = tree.audit_trace(5)
        
        # 验证追踪路径
        self.assertTrue(len(trace) > 0)
        self.assertEqual(trace[0][0], "Leaf[5]")
        self.assertEqual(trace[-1][0], "Root")
    
    def test_batch_verification(self):
        """测试批量验证"""
        tree = AuditMerkleTree()
        
        test_data = [f"Entry {i}".encode() for i in range(20)]
        for data in test_data:
            tree.add_leaf(data)
        
        # 生成多个证明
        proofs = []
        for i in [0, 5, 10, 15, 19]:
            proof = tree.get_inclusion_proof(i)
            proofs.append((proof, tree.root_hash))
        
        # 批量验证
        results = tree.batch_verify_inclusion_proofs(proofs)
        
        self.assertTrue(all(results))


class TestMerkleTreeEdgeCases(unittest.TestCase):
    """测试默克尔树边界情况"""
    
    def test_single_leaf_tree(self):
        """测试单叶子树"""
        tree = MerkleTree()
        tree.add_leaf(b"Single leaf")
        
        self.assertEqual(tree.tree_size, 1)
        
        # 包含证明
        proof = tree.get_inclusion_proof(0)
        is_valid = MerkleTree.verify_inclusion_proof_with_data(
            b"Single leaf", proof, tree.root_hash
        )
        self.assertTrue(is_valid)
        
        # 一致性证明
        cons_proof = tree.get_consistency_proof(1)
        is_valid = MerkleTree.verify_consistency_proof(cons_proof, tree.root_hash)
        self.assertTrue(is_valid)
    
    def test_power_of_two_leaves(self):
        """测试2的幂次方叶子数"""
        tree = MerkleTree()
        
        for i in range(8):
            tree.add_leaf(f"Leaf {i}".encode())
        
        self.assertEqual(tree.tree_size, 8)
        
        # 所有叶子验证
        for i in range(8):
            proof = tree.get_inclusion_proof(i)
            is_valid = MerkleTree.verify_inclusion_proof_with_data(
                f"Leaf {i}".encode(), proof, tree.root_hash
            )
            self.assertTrue(is_valid)
    
    def test_invalid_leaf_index(self):
        """测试无效叶子索引"""
        tree = MerkleTree()
        tree.add_leaf(b"Leaf")
        
        with self.assertRaises(ValueError):
            tree.get_inclusion_proof(1)
        
        with self.assertRaises(ValueError):
            tree.get_inclusion_proof(-1)
    
    def test_invalid_consistency_proof_size(self):
        """测试无效一致性证明大小"""
        tree = MerkleTree()
        tree.add_leaf(b"Leaf")
        
        with self.assertRaises(ValueError):
            tree.get_consistency_proof(0)
        
        with self.assertRaises(ValueError):
            tree.get_consistency_proof(2)


if __name__ == '__main__':
    unittest.main()
