"""
审计器核心实现。
"""

import secrets
import time
from typing import Dict, List

from .models import AuditResult, VerificationResult, AuditReport
from ..crypto import Ed25519Verifier, SignedTreeHead
from ..merkle import MerkleTree, InclusionProof, ConsistencyProof
from ..storage import StorageEngine


class Auditor:
    """审计节点。"""

    def __init__(self, public_key: bytes, storage_path: str):
        self._verifier = Ed25519Verifier(public_key)
        self._public_key = public_key
        self._storage = StorageEngine(base_path=storage_path, enable_encryption=False)
        self._total_verifications = 0
        self._failed_verifications = 0

    # ---------- STH 签名验证 ----------

    def verify_sth_signature(self, sth: SignedTreeHead) -> VerificationResult:
        try:
            is_valid = self._verifier.verify_sth(
                sth.tree_size, sth.root_hash, sth.timestamp, sth.signature
            )
            if is_valid:
                return VerificationResult(
                    result=AuditResult.PASS,
                    message=f"STH 签名验证通过 (树大小: {sth.tree_size})",
                    details={'tree_size': sth.tree_size, 'timestamp': sth.timestamp},
                )
            self._failed_verifications += 1
            return VerificationResult(
                result=AuditResult.FAIL,
                message="STH 签名验证失败",
                details={'tree_size': sth.tree_size, 'timestamp': sth.timestamp},
            )
        except Exception as e:
            self._failed_verifications += 1
            return VerificationResult(
                result=AuditResult.ERROR,
                message=f"STH 签名验证异常: {str(e)}",
            )

    # ---------- 包含证明验证 ----------

    def verify_inclusion_proof(
        self,
        leaf_data: bytes,
        proof: InclusionProof,
        root_hash: bytes,
    ) -> VerificationResult:
        try:
            is_valid = MerkleTree.verify_inclusion_proof_with_data(leaf_data, proof, root_hash)
            if is_valid:
                self._total_verifications += 1
                return VerificationResult(
                    result=AuditResult.PASS,
                    message=f"包含证明验证通过 (索引: {proof.leaf_index})",
                    details={'leaf_index': proof.leaf_index, 'tree_size': proof.tree_size},
                )
            self._failed_verifications += 1
            return VerificationResult(
                result=AuditResult.FAIL,
                message=f"包含证明验证失败 (索引: {proof.leaf_index})",
                details={'leaf_index': proof.leaf_index, 'tree_size': proof.tree_size},
            )
        except Exception as e:
            self._failed_verifications += 1
            return VerificationResult(
                result=AuditResult.ERROR,
                message=f"包含证明验证异常: {str(e)}",
            )

    # ---------- 一致性证明验证 ----------

    def verify_consistency_proof(
        self,
        proof: ConsistencyProof,
        new_root_hash: bytes,
    ) -> VerificationResult:
        try:
            # 使用重计算方法验证（更可靠）
            leaves = self._storage.merkle_tree._leaves
            is_valid = MerkleTree.verify_consistency_proof(proof, new_root_hash, leaves)
            if is_valid:
                self._total_verifications += 1
                return VerificationResult(
                    result=AuditResult.PASS,
                    message=f"一致性证明验证通过 (旧树: {proof.old_tree_size} -> 新树: {proof.new_tree_size})",
                    details={
                        'old_tree_size': proof.old_tree_size,
                        'new_tree_size': proof.new_tree_size,
                    },
                )
            self._failed_verifications += 1
            return VerificationResult(
                result=AuditResult.FAIL,
                message=f"一致性证明验证失败 (旧树: {proof.old_tree_size} -> 新树: {proof.new_tree_size})",
                details={
                    'old_tree_size': proof.old_tree_size,
                    'new_tree_size': proof.new_tree_size,
                },
            )
        except Exception as e:
            self._failed_verifications += 1
            return VerificationResult(
                result=AuditResult.ERROR,
                message=f"一致性证明验证异常: {str(e)}",
            )

    # ---------- 组合验证 ----------

    def verify_log_entry(
        self,
        leaf_data: bytes,
        leaf_index: int,
        root_hash: bytes,
        proof: InclusionProof,
    ) -> VerificationResult:
        """综合验证单个日志条目。"""
        if proof.leaf_index != leaf_index:
            return VerificationResult(
                result=AuditResult.FAIL,
                message=f"叶子索引不匹配: 期望 {leaf_index}, 实际 {proof.leaf_index}",
            )
        if proof.tree_size <= leaf_index:
            return VerificationResult(
                result=AuditResult.FAIL,
                message=f"树大小小于叶子索引: 树大小={proof.tree_size}, 索引={leaf_index}",
            )
        return self.verify_inclusion_proof(leaf_data, proof, root_hash)

    def verify_sth_chain(self, sth_records: List[SignedTreeHead]) -> VerificationResult:
        """验证 STH 链的连续性与签名。"""
        if not sth_records:
            return VerificationResult(result=AuditResult.PASS, message="STH 链为空,跳过验证")

        try:
            first_result = self.verify_sth_signature(sth_records[0])
            if not first_result.is_pass():
                return first_result

            for i in range(1, len(sth_records)):
                prev_sth = sth_records[i - 1]
                curr_sth = sth_records[i]

                sig_result = self.verify_sth_signature(curr_sth)
                if not sig_result.is_pass():
                    return sig_result

                if curr_sth.timestamp < prev_sth.timestamp:
                    self._failed_verifications += 1
                    return VerificationResult(
                        result=AuditResult.FAIL,
                        message=f"STH 时间戳倒序: 索引 {i - 1} 时间={prev_sth.timestamp}, 索引 {i} 时间={curr_sth.timestamp}",
                    )

                if curr_sth.tree_size < prev_sth.tree_size:
                    self._failed_verifications += 1
                    return VerificationResult(
                        result=AuditResult.FAIL,
                        message=f"STH 树大小递减: 索引 {i - 1} 大小={prev_sth.tree_size}, 索引 {i} 大小={curr_sth.tree_size}",
                    )

                if curr_sth.tree_size > prev_sth.tree_size:
                    # 使用重计算方法直接验证 STH 链的一致性
                    # 从存储获取叶子数据，验证 prev_sth 和 curr_sth 的根哈希是否与叶子一致
                    leaves = self._storage.merkle_tree._leaves
                    if prev_sth.tree_size > len(leaves) or curr_sth.tree_size > len(leaves):
                        self._failed_verifications += 1
                        return VerificationResult(
                            result=AuditResult.FAIL,
                            message=f"一致性证明验证失败: 叶子数量不足 (旧树: {prev_sth.tree_size} -> 新树: {curr_sth.tree_size}, 可用叶子: {len(leaves)})",
                        )
                    
                    # 验证旧树根与叶子的一致性
                    old_leaves = leaves[:prev_sth.tree_size]
                    from src.merkle._tree_ops import compute_root_from_leaves
                    computed_old_root = compute_root_from_leaves(old_leaves)
                    if computed_old_root != prev_sth.root_hash:
                        self._failed_verifications += 1
                        return VerificationResult(
                            result=AuditResult.FAIL,
                            message=f"一致性证明验证失败 (旧树: {prev_sth.tree_size} -> 新树: {curr_sth.tree_size}): 旧树根不匹配",
                        )
                    
                    # 验证新树根与叶子的一致性
                    new_leaves = leaves[:curr_sth.tree_size]
                    computed_new_root = compute_root_from_leaves(new_leaves)
                    if computed_new_root != curr_sth.root_hash:
                        self._failed_verifications += 1
                        return VerificationResult(
                            result=AuditResult.FAIL,
                            message=f"一致性证明验证失败 (旧树: {prev_sth.tree_size} -> 新树: {curr_sth.tree_size}): 新树根不匹配",
                        )
                    
                    self._total_verifications += 1

            self._total_verifications += 1
            return VerificationResult(
                result=AuditResult.PASS,
                message=f"STH 链验证通过 ({len(sth_records)} 个 STH)",
                details={'sth_count': len(sth_records)},
            )
        except Exception as e:
            self._failed_verifications += 1
            return VerificationResult(
                result=AuditResult.ERROR,
                message=f"STH 链验证异常: {str(e)}",
            )

    # ---------- 抽样 / 完整审计 ----------

    def audit_random_entries(
        self,
        sample_size: int,
        sth: SignedTreeHead,
    ) -> List[VerificationResult]:
        results: List[VerificationResult] = []
        tree_size = sth.tree_size
        if tree_size == 0:
            return results

        indices: set = set()
        max_samples = min(sample_size, tree_size)
        while len(indices) < max_samples:
            indices.add(secrets.randbelow(tree_size))

        for leaf_index in indices:
            try:
                entry = self._storage.get_entry(leaf_index)
                if entry is None:
                    results.append(
                        VerificationResult(
                            result=AuditResult.ERROR,
                            message=f"无法获取索引 {leaf_index} 的条目",
                        )
                    )
                    continue
                proof = self._storage.merkle_tree.get_inclusion_proof(leaf_index)
                result = self.verify_log_entry(entry.data, leaf_index, sth.root_hash, proof)
                results.append(result)
            except Exception as e:
                results.append(
                    VerificationResult(
                        result=AuditResult.ERROR,
                        message=f"审计索引 {leaf_index} 异常: {str(e)}",
                    )
                )
        return results

    def full_audit(self, sth: SignedTreeHead) -> AuditReport:
        start_time = time.time()
        results: List[VerificationResult] = []
        
        # 重新加载树状态以确保使用最新数据
        self._storage._load_or_rebuild_tree()

        results.append(self.verify_sth_signature(sth))

        sth_records = self._storage.get_all_sth_records()
        sth_objects = [
            SignedTreeHead(tree_size=r[0], root_hash=r[1], timestamp=r[2], signature=r[3])
            for r in sth_records
        ]
        if len(sth_objects) > 1:
            results.append(self.verify_sth_chain(sth_objects))

        sample_results = self.audit_random_entries(min(100, sth.tree_size), sth)
        results.extend(sample_results)

        # 验证存储完整性：比较 STH 的根哈希与从索引重建的树根哈希
        rebuilt_root = self._storage.get_rebuilt_root_hash()
        
        if rebuilt_root != sth.root_hash:
            results.append(
                VerificationResult(result=AuditResult.FAIL, message="存储完整性验证失败")
            )

        passed = sum(1 for r in results if r.is_pass())
        failed = sum(1 for r in results if r.is_fail())
        duration_ms = (time.time() - start_time) * 1000

        return AuditReport(
            timestamp=int(time.time()),
            verified_items=len(results),
            passed_items=passed,
            failed_items=failed,
            results=results,
            duration_ms=duration_ms,
        )

    # ---------- 属性 / 关闭 ----------

    @property
    def statistics(self) -> Dict[str, int]:
        return {
            'total_verifications': self._total_verifications,
            'failed_verifications': self._failed_verifications,
        }

    def close(self) -> None:
        self._storage.close()
