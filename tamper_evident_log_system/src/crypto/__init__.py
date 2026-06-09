"""
密码学工具包

提供域隔离哈希、Ed25519签名/验签、AES-GCM加密以及密钥管理。
"""

from .hash_utils import DomainSeparatedHash, LEAF_PREFIX, INTERNAL_PREFIX
from .signatures import Ed25519Signer, Ed25519Verifier
from .encryption import AESCipher
from .key_manager import KeyManager
from .sth import SignedTreeHead
from .utils import generate_secure_random, constant_time_compare

__all__ = [
    "DomainSeparatedHash",
    "LEAF_PREFIX",
    "INTERNAL_PREFIX",
    "Ed25519Signer",
    "Ed25519Verifier",
    "AESCipher",
    "KeyManager",
    "SignedTreeHead",
    "generate_secure_random",
    "constant_time_compare",
]
