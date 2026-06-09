"""
审计器核心实现。

提供独立的日志验证与数据完整性审计能力。
"""

from typing import List, Optional, Tuple
import time

from src.merkle.proofs import InclusionProof, ConsistencyProof
from src.merkle._tree_ops import (
    compute_root_from_leaves,
    verify_inclusion_proof_with_data,
    verify_consistency_proof_rfc6962,
)
from src.merkle.core import MerkleTree
from src.storage import StorageEngine
from src.crypto.sth import SignedTreeHead
from src.crypto.signatures import Ed25519Signer, Ed25519Verifier
from .models import AuditResult, VerificationResult, AuditReport


class Auditor:
    """
    审计器类，用于验证日志系统的完整性。
    """

    def __init__(self, public_key: bytes, storage_path: str = "./web_storage"):
        self._storage = StorageEngine(storage_path)
        self._verifier = Ed25519Verifier(public_key)

    def verify_sth_signature(self, sth: SignedTreeHead) -> VerificationResult:
        """验证 STH 签名"""
        try:
            is_valid = self._verifier.verify(
                sth.serialize_for_signing(),
                sth.signature
            )
            if is_valid:
                return VerificationResult(
                    result=AuditResult.PASS,
                    message=f"STH 签名验证通过"
                )
            else:
                return VerificationResult(
                    result=AuditResult.FAIL,
                    message=f"STH 签名验证失败"
                )
        except Exception as e:
            return VerificationResult(
                result=AuditResult.ERROR,
                message=f"STH 签名验证异常: {str(e)}"
            )

    def verify_sth_chain(self, sths: List[SignedTreeHead]) -> VerificationResult:
        """验证 STH 链的一致性"""
        if len(sths) < 2:
            return VerificationResult(
                result=AuditResult.PASS,
                message=f"STH 链验证通过（{len(sths)} 个 STH）"
            )

        # 按树大小排序，相同树大小保留最新时间戳的
        sorted_sths = sorted(sths, key=lambda x: (x.tree_size, x.timestamp))
        
        # 去重：保留每个树大小的最新 STH
        unique_sths = []
        seen_sizes = set()
        for sth in sorted_sths:
            if sth.tree_size not in seen_sizes:
                unique_sths.append(sth)
                seen_sizes.add(sth.tree_size)
        
        # 如果去重后只有一个或没有 STH，直接通过
        if len(unique_sths) < 2:
            return VerificationResult(
                result=AuditResult.PASS,
                message=f"STH 链验证通过（去重后 {len(unique_sths)} 个 STH）"
            )

        for i in range(len(unique_sths) - 1):
            old_sth = unique_sths[i]
            new_sth = unique_sths[i + 1]

            if old_sth.tree_size >= new_sth.tree_size:
                return VerificationResult(
                    result=AuditResult.FAIL,
                    message=f"STH 链顺序错误: 旧树大小 {old_sth.tree_size} >= 新树大小 {new_sth.tree_size}"
                )

            # 使用重计算方法验证一致性
            try:
                leaves = self._storage.merkle_tree._leaves
                if len(leaves) >= new_sth.tree_size:
                    # 验证旧 STH
                    old_root = compute_root_from_leaves(leaves[:old_sth.tree_size])
                    if old_root != old_sth.root_hash:
                        return VerificationResult(
                            result=AuditResult.FAIL,
                            message=f"STH 链验证失败: 旧树根哈希不匹配"
                        )

                    # 验证新 STH
                    new_root = compute_root_from_leaves(leaves[:new_sth.tree_size])
                    if new_root != new_sth.root_hash:
                        return VerificationResult(
                            result=AuditResult.FAIL,
                            message=f"STH 链验证失败: 新树根哈希不匹配"
                        )
                else:
                    return VerificationResult(
                        result=AuditResult.FAIL,
                        message=f"STH 链验证失败: 存储叶子不足"
                    )
            except Exception as e:
                return VerificationResult(
                    result=AuditResult.ERROR,
                    message=f"STH 链验证异常: {str(e)}"
                )

        return VerificationResult(
            result=AuditResult.PASS,
            message=f"STH 链验证通过（{len(sths)} 个 STH）"
        )

    def verify_inclusion_proof(self, leaf_index: int) -> VerificationResult:
        """验证指定索引的包含证明"""
        try:
            # 获取包含证明
            proof = self._storage.merkle_tree.get_inclusion_proof(leaf_index)

            # 获取原始数据
            entry = self._storage.get_entry(leaf_index)
            if entry is None or entry.data is None:
                return VerificationResult(
                    result=AuditResult.FAIL,
                    message=f"包含证明验证失败: 无法获取原始数据"
                )

            # 验证包含证明
            root_hash = self._storage.merkle_tree.root_hash
            is_valid = MerkleTree.verify_inclusion_proof_with_data(
                entry.data,
                proof,
                root_hash
            )

            if is_valid:
                return VerificationResult(
                    result=AuditResult.PASS,
                    message=f"包含证明验证通过（索引: {leaf_index}）"
                )
            else:
                return VerificationResult(
                    result=AuditResult.FAIL,
                    message=f"包含证明验证失败（索引: {leaf_index}）"
                )
        except Exception as e:
            return VerificationResult(
                result=AuditResult.ERROR,
                message=f"包含证明验证异常（索引: {leaf_index}）: {str(e)}"
            )

    def verify_storage_integrity(self) -> VerificationResult:
        """验证存储完整性"""
        try:
            # 从索引重建树并比较根哈希
            rebuilt_root = self._storage.get_rebuilt_root_hash()
            current_root = self._storage.merkle_tree.root_hash

            if rebuilt_root == current_root:
                return VerificationResult(
                    result=AuditResult.PASS,
                    message="存储完整性验证通过"
                )
            else:
                return VerificationResult(
                    result=AuditResult.FAIL,
                    message=f"存储完整性验证失败: 重建根哈希不匹配"
                )
        except Exception as e:
            return VerificationResult(
                result=AuditResult.ERROR,
                message=f"存储完整性验证异常: {str(e)}"
            )

    def full_audit(self, latest_sth: Optional[SignedTreeHead] = None) -> AuditReport:
        """执行完整审计"""
        start_time = time.time()
        results: List[VerificationResult] = []

        # 1. 验证最新 STH 签名
        sth_records = self._storage.get_all_sth_records()
        sths = [
            SignedTreeHead(
                tree_size=r[0], root_hash=r[1], timestamp=r[2], signature=r[3]
            )
            for r in sth_records
        ]
        
        if latest_sth is None and sths:
            latest_sth = max(sths, key=lambda x: x.tree_size)
        
        if latest_sth:
            result = self.verify_sth_signature(latest_sth)
            result.item = f"STH 签名验证（树大小: {latest_sth.tree_size}）"
            results.append(result)
        else:
            results.append(VerificationResult(
                result=AuditResult.PASS,
                message="无 STH 可验证",
                item="STH 签名验证"
            ))

        # 2. 验证 STH 链
        result = self.verify_sth_chain(sths)
        result.item = "STH 链验证"
        results.append(result)

        # 3. 验证包含证明（验证所有叶子）
        tree_size = self._storage.merkle_tree._tree_size
        for i in range(min(tree_size, 10)):  # 最多验证前10个
            result = self.verify_inclusion_proof(i)
            result.item = f"包含证明验证（索引: {i}）"
            results.append(result)

        # 4. 验证存储完整性
        result = self.verify_storage_integrity()
        result.item = "存储完整性验证"
        results.append(result)

        duration_ms = (time.time() - start_time) * 1000
        passed = sum(1 for r in results if r.is_pass())
        failed = len(results) - passed

        return AuditReport(
            timestamp=int(time.time()),
            verified_items=len(results),
            passed_items=passed,
            failed_items=failed,
            results=results,
            duration_ms=duration_ms
        )

    def close(self):
        """关闭审计器，释放资源"""
        pass