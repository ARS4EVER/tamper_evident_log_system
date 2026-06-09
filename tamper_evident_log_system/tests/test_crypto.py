"""
密码学工具测试
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.crypto import (
    DomainSeparatedHash,
    Ed25519Signer,
    Ed25519Verifier,
    AESCipher,
    KeyManager,
    SignedTreeHead,
    constant_time_compare,
    generate_secure_random
)


class TestDomainSeparatedHash(unittest.TestCase):
    """测试域隔离哈希"""
    
    def test_hash_leaf_prefix(self):
        """测试叶子节点哈希前缀"""
        data = b"test data"
        leaf_hash = DomainSeparatedHash.hash_leaf(data)
        
        # 验证输出长度
        self.assertEqual(len(leaf_hash), 32)
        
        # 验证相同输入产生相同输出
        leaf_hash2 = DomainSeparatedHash.hash_leaf(data)
        self.assertEqual(leaf_hash, leaf_hash2)
    
    def test_hash_internal_prefix(self):
        """测试内部节点哈希前缀"""
        left = b"left child hash" + b'\x00' * 16
        right = b"right child hash" + b'\x00' * 16
        left = left[:32]
        right = right[:32]
        
        internal_hash = DomainSeparatedHash.hash_internal(left, right)
        
        # 验证输出长度
        self.assertEqual(len(internal_hash), 32)
        
        # 验证相同输入产生相同输出
        internal_hash2 = DomainSeparatedHash.hash_internal(left, right)
        self.assertEqual(internal_hash, internal_hash2)
    
    def test_domain_separation(self):
        """测试域隔离 - 相同数据不同前缀产生不同哈希"""
        data = b"same data"
        
        leaf = DomainSeparatedHash.hash_leaf(data)
        direct = DomainSeparatedHash.hash_bytes(data)
        
        # 叶子哈希应该与直接哈希不同 (因为前缀不同)
        self.assertNotEqual(leaf, direct)
    
    def test_second_preimage_resistance(self):
        """测试第二原像攻击防护"""
        # 内部节点哈希
        internal = DomainSeparatedHash.hash_internal(
            b'\x00' * 32,
            b'\x01' * 32
        )
        
        # 尝试用内部节点哈希欺骗叶子验证
        # 由于域隔离,应该无法匹配
        leaf_of_internal = DomainSeparatedHash.hash_leaf(internal)
        
        self.assertNotEqual(leaf_of_internal, internal)


class TestEd25519Signature(unittest.TestCase):
    """测试Ed25519签名"""
    
    def test_key_generation(self):
        """测试密钥生成"""
        signer = Ed25519Signer()
        
        # 验证公钥长度
        self.assertEqual(len(signer.public_key_bytes), 32)
        
        # 验证私钥长度
        self.assertEqual(len(signer.private_key_bytes), 32)
    
    def test_sign_and_verify(self):
        """测试签名和验签"""
        signer = Ed25519Signer()
        message = b"Test message for signing"
        
        signature = signer.sign(message)
        
        # 验证签名长度
        self.assertEqual(len(signature), 64)
        
        # 验证签名
        verifier = Ed25519Verifier(signer.public_key_bytes)
        self.assertTrue(verifier.verify(message, signature))
    
    def test_sign_sth(self):
        """测试STH签名"""
        signer = Ed25519Signer()
        tree_size = 1000
        root_hash = b'\x01' * 32
        timestamp = 1234567890
        
        signature = signer.sign_sth(tree_size, root_hash, timestamp)
        
        self.assertEqual(len(signature), 64)
        
        # 验证STH签名
        verifier = Ed25519Verifier(signer.public_key_bytes)
        self.assertTrue(verifier.verify_sth(tree_size, root_hash, timestamp, signature))
    
    def test_deterministic_signature(self):
        """测试确定性签名 - 相同消息产生相同签名"""
        # 使用固定私钥
        private_bytes = b'\x01' * 32
        signer = Ed25519Signer()
        message = b"Deterministic test"
        
        sig1 = signer.sign(message)
        sig2 = signer.sign(message)
        
        # Ed25519签名是确定性的
        self.assertEqual(sig1, sig2)
    
    def test_wrong_signature_rejected(self):
        """测试错误签名被拒绝"""
        signer = Ed25519Signer()
        verifier = Ed25519Verifier(signer.public_key_bytes)
        
        message = b"Original message"
        wrong_message = b"Tampered message"
        
        signature = signer.sign(message)
        
        # 用错误消息验证应该失败
        self.assertFalse(verifier.verify(wrong_message, signature))
    
    def test_tampered_signature_rejected(self):
        """测试篡改签名被拒绝"""
        signer = Ed25519Signer()
        verifier = Ed25519Verifier(signer.public_key_bytes)
        
        message = b"Test message"
        signature = signer.sign(message)
        
        # 篡改签名
        tampered_sig = bytearray(signature)
        tampered_sig[0] ^= 0xFF
        tampered_sig = bytes(tampered_sig)
        
        self.assertFalse(verifier.verify(message, tampered_sig))


class TestAESCipher(unittest.TestCase):
    """测试AES-256-GCM加密"""
    
    def test_encrypt_decrypt(self):
        """测试加密和解密"""
        cipher = AESCipher()
        plaintext = b"Secret message to encrypt"
        
        nonce, ciphertext = cipher.encrypt(plaintext)
        
        # 验证nonce长度
        self.assertEqual(len(nonce), 12)
        
        # 解密
        decrypted = cipher.decrypt(nonce, ciphertext)
        self.assertEqual(decrypted, plaintext)
    
    def test_encrypt_with_aad(self):
        """测试带额外认证数据的加密"""
        cipher = AESCipher()
        plaintext = b"Message with AAD"
        aad = b"Additional authenticated data"
        
        nonce, ciphertext = cipher.encrypt(plaintext, aad)
        
        # 使用相同AAD解密
        decrypted = cipher.decrypt(nonce, ciphertext, aad)
        self.assertEqual(decrypted, plaintext)
    
    def test_wrong_aad_rejected(self):
        """测试错误AAD被拒绝"""
        cipher = AESCipher()
        plaintext = b"Message"
        correct_aad = b"Correct AAD"
        wrong_aad = b"Wrong AAD"
        
        nonce, ciphertext = cipher.encrypt(plaintext, correct_aad)
        
        # 用错误AAD解密应该失败
        with self.assertRaises(Exception):
            cipher.decrypt(nonce, ciphertext, wrong_aad)
    
    def test_different_nonces(self):
        """测试不同nonce产生不同密文"""
        cipher = AESCipher()
        plaintext = b"Same message"
        
        nonce1, ciphertext1 = cipher.encrypt(plaintext)
        nonce2, ciphertext2 = cipher.encrypt(plaintext)
        
        # 不同nonce应该产生不同密文
        self.assertNotEqual(nonce1, nonce2)
        self.assertNotEqual(ciphertext1, ciphertext2)


class TestKeyManager(unittest.TestCase):
    """测试密钥管理器"""
    
    def test_generate_signing_key(self):
        """测试生成签名密钥"""
        km = KeyManager()
        signer = km.generate_signing_key()
        
        self.assertIsNotNone(signer)
        self.assertEqual(len(signer.public_key_bytes), 32)
    
    def test_generate_encryption_key(self):
        """测试生成加密密钥"""
        km = KeyManager()
        cipher = km.generate_encryption_key()
        
        self.assertIsNotNone(cipher)
    
    def test_set_and_get_keys(self):
        """测试设置和获取密钥"""
        km = KeyManager()
        
        # 设置签名密钥
        signer1 = km.generate_signing_key()
        km.set_signing_key(signer1.private_key_bytes)
        
        # 获取应该是同一个密钥
        signer2 = km.get_signing_key()
        self.assertEqual(signer1.public_key_bytes, signer2.public_key_bytes)


class TestSignedTreeHead(unittest.TestCase):
    """测试签名树根"""
    
    def test_sth_serialization(self):
        """测试STH序列化"""
        sth = SignedTreeHead(
            tree_size=1000,
            root_hash=b'\xAB' * 32,
            timestamp=1234567890,
            signature=b'\xCD' * 64
        )
        
        # 序列化
        data = sth.to_bytes()
        
        # 验证序列化成功
        self.assertIsNotNone(data)
        
        # 反序列化
        sth2 = SignedTreeHead.from_bytes(data)
        
        self.assertEqual(sth.tree_size, sth2.tree_size)
        self.assertEqual(sth.root_hash, sth2.root_hash)
        self.assertEqual(sth.timestamp, sth2.timestamp)
        self.assertEqual(sth.signature, sth2.signature)


class TestConstantTimeCompare(unittest.TestCase):
    """测试恒定时间比较"""
    
    def test_equal_values(self):
        """测试相等的值"""
        a = b'\x01\x02\x03\x04'
        b_val = b'\x01\x02\x03\x04'
        
        self.assertTrue(constant_time_compare(a, b_val))
    
    def test_different_values(self):
        """测试不同的值"""
        a = b'\x01\x02\x03\x04'
        b_val = b'\x01\x02\x03\x05'
        
        self.assertFalse(constant_time_compare(a, b_val))
    
    def test_different_lengths(self):
        """测试不同长度"""
        a = b'\x01\x02\x03'
        b_val = b'\x01\x02\x03\x04'
        
        self.assertFalse(constant_time_compare(a, b_val))


if __name__ == '__main__':
    unittest.main()
