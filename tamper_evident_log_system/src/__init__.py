"""
tamper_evident_log_system - 可防篡改审计日志系统

提供基于 Merkle Tree 与 Ed25519 签名的不可篡改日志系统,包括:
- crypto: 密码学基元 (哈希 / 签名 / 加密 / 密钥管理 / STH)
- merkle: 默克尔树核心与证明
- storage: 追加式存储引擎
- server: 日志服务器
- auditor: 审计节点
"""

from .crypto import (
    DomainSeparatedHash,
    Ed25519Signer,
    Ed25519Verifier,
    AESCipher,
    KeyManager,
    SignedTreeHead,
    generate_secure_random,
    constant_time_compare,
)
from .merkle import MerkleProof, InclusionProof, ConsistencyProof, MerkleTree, AuditMerkleTree
from .storage import LogEntry, StorageMetadata, StorageEngine, HierarchicalHashStore
from .server import ServerConfig, LogServer, STHPublisher
from .auditor import AuditResult, VerificationResult, AuditReport, Auditor, ContinuousAuditor

__all__ = [
    # crypto
    "DomainSeparatedHash",
    "Ed25519Signer",
    "Ed25519Verifier",
    "AESCipher",
    "KeyManager",
    "SignedTreeHead",
    "generate_secure_random",
    "constant_time_compare",
    # merkle
    "MerkleProof",
    "InclusionProof",
    "ConsistencyProof",
    "MerkleTree",
    "AuditMerkleTree",
    # storage
    "LogEntry",
    "StorageMetadata",
    "StorageEngine",
    "HierarchicalHashStore",
    # server
    "ServerConfig",
    "LogServer",
    "STHPublisher",
    # auditor
    "AuditResult",
    "VerificationResult",
    "AuditReport",
    "Auditor",
    "ContinuousAuditor",
]

__version__ = "1.0.0"
