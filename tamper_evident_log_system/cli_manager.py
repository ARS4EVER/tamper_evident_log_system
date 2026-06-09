"""
防篡改审计日志系统 - 本地命令行管理工具

提供纯命令行界面的日志管理、查询、验证和审计功能。
"""

import sys
import os
import json
import time
import argparse
from typing import Optional, List

# 添加 src 到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.server import LogServer, ServerConfig
from src.auditor import Auditor
from src.crypto.sth import SignedTreeHead


class Colors:
    """终端颜色 - 简化版本，兼容Windows"""
    GREEN = ''
    RED = ''
    YELLOW = ''
    BLUE = ''
    CYAN = ''
    BOLD = ''
    END = ''


def print_success(msg: str):
    print(f"[OK] {msg}")


def print_error(msg: str):
    print(f"[FAIL] {msg}")


def print_warning(msg: str):
    print(f"[WARN] {msg}")


def print_info(msg: str):
    print(f"[INFO] {msg}")


def print_header(msg: str):
    print(f"\n{msg}")
    print("=" * 50)


class LocalLogManager:
    """本地日志管理器"""

    def __init__(self, storage_path: str = "./data"):
        self.storage_path = storage_path
        self.config = ServerConfig(storage_path=storage_path, sth_interval=10)
        self.server = LogServer(self.config)
        self.auditor = Auditor(self.server.public_key, storage_path)

    def submit_log(self, data: str, timestamp: Optional[int] = None) -> dict:
        """提交日志"""
        if timestamp is None:
            timestamp = int(time.time())

        try:
            index = self.server.submit_log(data.encode('utf-8'), timestamp)
            return {
                "success": True,
                "index": index,
                "message": f"日志已提交，索引: {index}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def query_log(self, index: int) -> dict:
        """查询日志"""
        try:
            entry = self.server.get_log_entry(index)
            if entry is None:
                return {
                    "success": False,
                    "error": f"索引 {index} 不存在"
                }

            # 获取包含证明
            proof = self.server.get_inclusion_proof(index)

            return {
                "success": True,
                "index": index,
                "data": entry.decode('utf-8') if entry else "",
                "timestamp": self.server._storage.get_entry(index).timestamp,
                "tree_size": proof.tree_size if proof else 0,
                "proof_hashes_count": len(proof.proof_hashes) if proof else 0
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def verify_inclusion(self, index: int) -> dict:
        """验证包含证明"""
        try:
            result = self.auditor.verify_inclusion_proof(index)
            return {
                "success": result.is_pass(),
                "message": result.message,
                "status": "PASS" if result.is_pass() else "FAIL"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def publish_sth(self) -> dict:
        """发布 STH"""
        try:
            sth = self.server.force_publish_sth()
            return {
                "success": True,
                "tree_size": sth.tree_size,
                "root_hash": sth.root_hash.hex()[:20] + "...",
                "timestamp": sth.timestamp,
                "message": "STH 发布成功"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def get_status(self) -> dict:
        """获取系统状态"""
        try:
            tree_size = self.server.tree_size
            latest_sth = self.server.get_latest_sth()

            status = {
                "success": True,
                "tree_size": tree_size,
                "storage_path": self.storage_path,
                "has_sth": latest_sth is not None
            }

            if latest_sth:
                status["latest_sth"] = {
                    "tree_size": latest_sth.tree_size,
                    "root_hash": latest_sth.root_hash.hex()[:20] + "...",
                    "timestamp": latest_sth.timestamp
                }

            return status
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def full_audit(self) -> dict:
        """执行完整审计"""
        try:
            latest_sth = self.server.get_latest_sth()
            report = self.auditor.full_audit(latest_sth)

            details = []
            for result in report.results:
                status = "PASS" if result.is_pass() else "FAIL" if result.is_fail() else "ERROR"
                item_name = result.item if result.item else "未知项目"
                details.append({
                    "status": status,
                    "item": item_name,
                    "message": result.message
                })

            return {
                "success": report.passed_items == report.verified_items,
                "verified_items": report.verified_items,
                "passed_items": report.passed_items,
                "failed_items": report.failed_items,
                "duration_ms": report.duration_ms,
                "details": details
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def list_logs(self, start: int = 0, limit: int = 10) -> dict:
        """列出日志"""
        try:
            entries = []
            tree_size = self.server.tree_size

            for i in range(start, min(start + limit, tree_size)):
                entry = self.server.get_log_entry(i)
                if entry:
                    entries.append({
                        "index": i,
                        "data": entry.decode('utf-8')[:50] + "..." if len(entry) > 50 else entry.decode('utf-8'),
                        "timestamp": self.server._storage.get_entry(i).timestamp
                    })

            return {
                "success": True,
                "total": tree_size,
                "start": start,
                "limit": limit,
                "entries": entries
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }


def interactive_mode(manager: LocalLogManager):
    """交互式模式"""
    print_header("防篡改审计日志系统 - 本地管理工具")
    print("输入 'help' 查看帮助，输入 'exit' 退出\n")

    while True:
        try:
            command = input("日志系统> ").strip()

            if not command:
                continue

            parts = command.split()
            cmd = parts[0].lower()
            args = parts[1:]

            if cmd == 'exit' or cmd == 'quit':
                print_info("再见！")
                break

            elif cmd == 'help':
                print_help()

            elif cmd == 'status':
                show_status(manager)

            elif cmd == 'submit':
                if not args:
                    print_error("请提供日志内容")
                    continue
                data = ' '.join(args)
                result = manager.submit_log(data)
                if result["success"]:
                    print_success(result["message"])
                else:
                    print_error(result.get("error", "提交失败"))

            elif cmd == 'query':
                if not args:
                    print_error("请提供索引")
                    continue
                try:
                    index = int(args[0])
                    result = manager.query_log(index)
                    if result["success"]:
                        print_info(f"索引: {result['index']}")
                        print_info(f"数据: {result['data']}")
                        print_info(f"时间戳: {result['timestamp']}")
                        print_info(f"树大小: {result['tree_size']}")
                    else:
                        print_error(result.get("error", "查询失败"))
                except ValueError:
                    print_error("索引必须是数字")

            elif cmd == 'verify':
                if not args:
                    print_error("请提供索引")
                    continue
                try:
                    index = int(args[0])
                    result = manager.verify_inclusion(index)
                    if result["success"]:
                        print_success(result["message"])
                    else:
                        print_error(result.get("message", "验证失败"))
                except ValueError:
                    print_error("索引必须是数字")

            elif cmd == 'publish':
                result = manager.publish_sth()
                if result["success"]:
                    print_success("STH 发布成功")
                    print_info(f"树大小: {result['tree_size']}")
                    print_info(f"根哈希: {result['root_hash']}")
                else:
                    print_error(result.get("error", "发布失败"))

            elif cmd == 'audit':
                print_info("正在执行完整审计...")
                result = manager.full_audit()
                if result["success"]:
                    print_success("审计通过！")
                else:
                    print_error("审计失败！")
                print_info(f"验证项目: {result['verified_items']}")
                print_info(f"通过: {result['passed_items']}")
                print_info(f"失败: {result['failed_items']}")
                print_info(f"耗时: {result['duration_ms']:.2f}ms")

                if "details" in result:
                    print("\n详细结果:")
                    for detail in result["details"]:
                        status_color = Colors.GREEN if detail["status"] == "PASS" else Colors.RED
                        print(f"  [{detail['status']}] {detail['item']}: {detail['message']}")

            elif cmd == 'list':
                start = int(args[0]) if args else 0
                limit = int(args[1]) if len(args) > 1 else 10
                result = manager.list_logs(start, limit)
                if result["success"]:
                    print_info(f"显示 {start} 到 {start + limit} (共 {result['total']} 条)")
                    for entry in result["entries"]:
                        print(f"  [{entry['index']}] {entry['data']} (时间: {entry['timestamp']})")
                else:
                    print_error(result.get("error", "列出失败"))

            else:
                print_error(f"未知命令: {cmd}")
                print_info("输入 'help' 查看帮助")

        except KeyboardInterrupt:
            print("\n")
            break
        except Exception as e:
            print_error(f"错误: {str(e)}")


def print_help():
    """打印帮助信息"""
    print_header("可用命令")
    commands = [
        ("status", "显示系统状态"),
        ("submit <数据>", "提交日志"),
        ("query <索引>", "查询日志"),
        ("verify <索引>", "验证包含证明"),
        ("publish", "发布 STH"),
        ("audit", "执行完整审计"),
        ("list [起始] [数量]", "列出日志"),
        ("help", "显示帮助"),
        ("exit", "退出"),
    ]
    for cmd, desc in commands:
        print(f"  {cmd:<25} {desc}")


def show_status(manager: LocalLogManager):
    """显示系统状态"""
    result = manager.get_status()
    if result["success"]:
        print_header("系统状态")
        print_info(f"存储路径: {result['storage_path']}")
        print_info(f"树大小: {result['tree_size']}")

        if result.get("has_sth"):
            sth = result["latest_sth"]
            print_info(f"最新 STH:")
            print_info(f"  树大小: {sth['tree_size']}")
            print_info(f"  根哈希: {sth['root_hash']}")
            print_info(f"  时间戳: {sth['timestamp']}")
        else:
            print_warning("暂无 STH")
    else:
        print_error(result.get("error", "获取状态失败"))


def main():
    parser = argparse.ArgumentParser(description='防篡改审计日志系统 - 本地管理工具')
    parser.add_argument('--storage', '-s', default='./data', help='存储路径 (默认: ./data)')
    parser.add_argument('--interactive', '-i', action='store_true', help='交互式模式')

    args = parser.parse_args()

    # 创建管理器
    manager = LocalLogManager(args.storage)

    # 默认进入交互式模式
    interactive_mode(manager)


if __name__ == "__main__":
    main()
