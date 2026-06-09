"""
防篡改审计日志系统 - 演示程序

本演示展示系统的完整工作流程:
1. 初始化日志服务器
2. 提交日志条目
3. 发布STH
4. 审计验证
"""

import sys
import os
import time
import tempfile
import shutil

# 添加项目根目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src import (
    LogServer,
    ServerConfig,
    Auditor,
    SignedTreeHead,
    AuditResult
)


def print_header(title: str):
    """打印标题"""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def print_step(step: str, description: str):
    """打印步骤"""
    print(f"\n[步骤 {step}] {description}")
    print("-" * 40)


def demo_basic_usage():
    """基本使用演示"""
    print_header("基本使用演示")
    
    # 创建临时存储目录
    temp_dir = tempfile.mkdtemp(prefix="audit_log_demo_")
    print(f"存储目录: {temp_dir}")
    
    try:
        # 1. 初始化服务器
        print_step("1", "初始化日志服务器")
        
        config = ServerConfig(
            sth_interval=10,      # 每10条日志发布一次STH
            sth_timeout=3600,    # 或每小时发布一次
            storage_path=temp_dir,
            enable_encryption=False
        )
        
        server = LogServer(config)
        print(f"服务器初始化完成")
        print(f"  - 公钥: {server.public_key.hex()[:32]}...")
        
        # 2. 提交日志
        print_step("2", "提交日志条目")
        
        num_logs = 25
        for i in range(num_logs):
            log_data = f"Transaction {i}: 金额=${100*(i+1)} 时间={time.time()}".encode()
            index = server.submit_log(log_data)
            if i < 5 or i >= num_logs - 3:
                print(f"  - 提交日志 #{index}: {log_data[:40]}...")
            elif i == 5:
                print(f"  - ... (共提交 {num_logs} 条日志)")
        
        print(f"\n当前树大小: {server.tree_size}")
        print(f"当前根哈希: {server.root_hash.hex()[:32]}...")
        
        # 3. 发布STH
        print_step("3", "发布签名树根 (STH)")
        
        sth = server.force_publish_sth()
        print(f"STH 已发布:")
        print(f"  - 树大小: {sth.tree_size}")
        print(f"  - 根哈希: {sth.root_hash.hex()[:32]}...")
        print(f"  - 时间戳: {sth.timestamp}")
        print(f"  - 签名: {sth.signature.hex()[:32]}...")
        
        # 4. 提交更多日志
        print_step("4", "提交更多日志并发布新STH")
        
        for i in range(5):
            server.submit_log(f"Additional log {i}".encode())
        
        sth2 = server.force_publish_sth()
        print(f"新 STH 已发布:")
        print(f"  - 树大小: {sth2.tree_size}")
        print(f"  - 新根哈希: {sth2.root_hash.hex()[:32]}...")
        
        # 5. 获取包含证明
        print_step("5", "获取并验证包含证明")
        
        test_index = 15
        proof = server.get_inclusion_proof(test_index)
        log_data = server.get_log_entry(test_index)
        
        print(f"验证日志 #{test_index}:")
        print(f"  - 数据: {log_data[:40]}...")
        print(f"  - 包含证明:")
        print(f"    - 叶子索引: {proof.leaf_index}")
        print(f"    - 证明路径长度: {len(proof.proof_hashes)}")
        print(f"    - 树大小: {proof.tree_size}")
        
        # 6. 初始化审计员
        print_step("6", "初始化审计节点并验证")
        
        auditor = Auditor(server.public_key, temp_dir)
        
        # 验证STH签名
        sig_result = auditor.verify_sth_signature(sth2)
        print(f"STH 签名验证: {sig_result.result.value} - {sig_result.message}")
        
        # 验证日志条目
        from src.merkle import MerkleTree
        is_valid = MerkleTree.verify_inclusion_proof_with_data(
            log_data, proof, sth2.root_hash
        )
        print(f"包含证明验证: {'通过' if is_valid else '失败'}")
        
        # 7. 一致性验证
        print_step("7", "验证一致性证明")
        
        cons_proof = server.get_consistency_proof(sth.tree_size)
        is_consistent = MerkleTree.verify_consistency_proof(cons_proof, sth2.root_hash)
        print(f"一致性证明 (旧树 {sth.tree_size} -> 新树 {sth2.tree_size}):")
        print(f"  - 验证结果: {'通过' if is_consistent else '失败'}")
        
        # 8. 完整审计
        print_step("8", "执行完整审计")
        
        report = auditor.full_audit(sth2)
        print(f"审计报告:")
        print(f"  - 验证项目: {report.verified_items}")
        print(f"  - 通过: {report.passed_items}")
        print(f"  - 失败: {report.failed_items}")
        print(f"  - 耗时: {report.duration_ms:.2f}毫秒")
        
        # 关闭
        auditor.close()
        server.close()
        
        print("\n" + "=" * 60)
        print("演示完成!")
        print("=" * 60)
        
    finally:
        # 清理临时目录
        shutil.rmtree(temp_dir, ignore_errors=True)


def demo_security_features():
    """安全特性演示"""
    print_header("安全特性演示")
    
    temp_dir = tempfile.mkdtemp(prefix="audit_security_demo_")
    print(f"存储目录: {temp_dir}")
    
    try:
        # 初始化
        config = ServerConfig(sth_interval=5, storage_path=temp_dir)
        server = LogServer(config)
        
        # 提交一些日志
        for i in range(10):
            server.submit_log(f"Secure log {i}".encode())
        
        sth = server.force_publish_sth()
        
        print("\n[安全测试 1] 验证STH签名不被篡改")
        
        # 篡改消息验证
        from src.crypto import Ed25519Verifier
        
        auditor = Auditor(server.public_key, temp_dir)
        
        # 篡改的STH
        tampered_sth = SignedTreeHead(
            tree_size=sth.tree_size,
            root_hash=sth.root_hash,
            timestamp=sth.timestamp,
            signature=b'\x00' * 64  # 错误的签名
        )
        
        result = auditor.verify_sth_signature(tampered_sth)
        print(f"  - 篡改签名检测: {result.result.value} (预期: fail)")
        
        print("\n[安全测试 2] 验证日志数据不被篡改")
        
        # 获取日志和证明
        log_index = 5
        log_data = server.get_log_entry(log_index)
        proof = server.get_inclusion_proof(log_index)
        
        # 篡改数据
        tampered_data = b"TAMPERED DATA"
        
        from src.merkle import MerkleTree
        is_valid = MerkleTree.verify_inclusion_proof_with_data(
            tampered_data, proof, sth.root_hash
        )
        print(f"  - 篡改数据检测: {'失败检测' if not is_valid else '未能检测'}")
        
        print("\n[安全测试 3] 验证根哈希一致性")
        
        wrong_root = b'\xFF' * 32
        is_valid = MerkleTree.verify_inclusion_proof_with_data(
            log_data, proof, wrong_root
        )
        print(f"  - 错误根哈希检测: {'失败检测' if not is_valid else '未能检测'}")
        
        auditor.close()
        server.close()
        
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def demo_performance():
    """性能演示"""
    print_header("性能演示")
    
    temp_dir = tempfile.mkdtemp(prefix="audit_perf_demo_")
    print(f"存储目录: {temp_dir}")
    
    try:
        config = ServerConfig(sth_interval=10000, storage_path=temp_dir)
        server = LogServer(config)
        
        # 批量提交性能
        print("\n[性能测试] 批量提交日志")
        
        batch_sizes = [100, 1000, 5000]
        
        for size in batch_sizes:
            start = time.time()
            for i in range(size):
                server.submit_log(f"Perf test {i}".encode())
            elapsed = time.time() - start
            
            print(f"  - 提交 {size} 条日志: {elapsed:.4f}秒 ({size/elapsed:.2f} 条/秒)")
        
        # 发布STH
        start = time.time()
        sth = server.force_publish_sth()
        sth_time = time.time() - start
        print(f"\n  - 发布STH: {sth_time:.4f}秒")
        
        # 验证性能
        print("\n[性能测试] 验证性能")
        
        import secrets
        auditor = Auditor(server.public_key, temp_dir)
        
        indices = [secrets.randbelow(sth.tree_size) for _ in range(100)]
        
        start = time.time()
        for idx in indices:
            proof = server.get_inclusion_proof(idx)
            log_data = server.get_log_entry(idx)
            from src.merkle import MerkleTree
            MerkleTree.verify_inclusion_proof_with_data(log_data, proof, sth.root_hash)
        elapsed = time.time() - start
        
        print(f"  - 100次随机验证: {elapsed:.4f}秒 ({100/elapsed:.2f} 验证/秒)")
        
        auditor.close()
        server.close()
        
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def main():
    """主函数"""
    print("\n")
    print("*" * 60)
    print("*" + " " * 18 + "防篡改审计日志系统" + " " * 18 + "*")
    print("*" + " " * 12 + "Tamper-Evident Audit Log System" + " " * 8 + "*")
    print("*" * 60)
    
    # 运行演示
    demo_basic_usage()
    demo_security_features()
    demo_performance()
    
    print("\n\n所有演示完成!")


if __name__ == '__main__':
    main()
