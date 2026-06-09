"""
防篡改审计日志系统 - GUI 版本

提供图形界面的日志管理、查询、验证和审计功能。
"""

import sys
import os
import time
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from typing import Optional, List

# 添加 src 到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.server import LogServer, ServerConfig
from src.auditor import Auditor, AuditResult


class LogSystemGUI:
    """防篡改审计日志系统 GUI"""

    def __init__(self, root):
        self.root = root
        self.root.title("防篡改审计日志系统")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)

        # 创建管理器
        self.storage_path = "./gui_data"
        self.config = ServerConfig(storage_path=self.storage_path, sth_interval=10)
        self.server = LogServer(self.config)
        # 确保审计器使用与服务器相同的存储路径
        self.auditor = Auditor(self.server.public_key, self.storage_path)
        # 确保审计器的存储引擎与服务器使用相同的路径
        self.auditor._storage = self.server._storage

        # 创建主框架
        self.create_widgets()

    def create_widgets(self):
        """创建所有组件"""
        # 顶部标签页
        self.tab_control = ttk.Notebook(self.root)
        
        # 标签页：状态概览
        self.tab_status = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_status, text="状态概览")
        self.create_status_tab()

        # 标签页：提交日志
        self.tab_submit = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_submit, text="提交日志")
        self.create_submit_tab()

        # 标签页：查询日志
        self.tab_query = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_query, text="查询日志")
        self.create_query_tab()

        # 标签页：验证审计
        self.tab_audit = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_audit, text="验证审计")
        self.create_audit_tab()

        # 标签页：日志列表
        self.tab_list = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_list, text="日志列表")
        self.create_list_tab()

        self.tab_control.pack(expand=1, fill="both")

    def create_status_tab(self):
        """状态概览标签页"""
        frame = ttk.LabelFrame(self.tab_status, text="系统状态")
        frame.pack(padx=10, pady=10, fill="both", expand=True)

        # 状态信息
        self.status_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=20)
        self.status_text.pack(padx=5, pady=5, fill="both", expand=True)
        self.status_text.config(state=tk.DISABLED)

        # 刷新按钮
        ttk.Button(frame, text="刷新状态", command=self.update_status).pack(pady=5)

        # 初始更新状态
        self.update_status()

    def create_submit_tab(self):
        """提交日志标签页"""
        frame = ttk.LabelFrame(self.tab_submit, text="提交新日志")
        frame.pack(padx=10, pady=10, fill="both", expand=True)

        # 日志内容输入
        ttk.Label(frame, text="日志内容：").pack(anchor=tk.W, padx=5)
        self.submit_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=10)
        self.submit_text.pack(padx=5, pady=5, fill="both", expand=True)

        # 提交按钮
        ttk.Button(frame, text="提交日志", command=self.submit_log).pack(pady=5)

        # 结果显示
        self.submit_result = ttk.Label(frame, text="", foreground="green")
        self.submit_result.pack(pady=5)

    def create_query_tab(self):
        """查询日志标签页"""
        frame = ttk.LabelFrame(self.tab_query, text="查询日志")
        frame.pack(padx=10, pady=10, fill="both", expand=True)

        # 索引输入
        input_frame = ttk.Frame(frame)
        input_frame.pack(padx=5, pady=5, fill="x")
        
        ttk.Label(input_frame, text="日志索引：").pack(side=tk.LEFT, padx=5)
        self.query_index = ttk.Entry(input_frame, width=10)
        self.query_index.pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text="查询", command=self.query_log).pack(side=tk.LEFT, padx=5)

        # 查询结果
        self.query_result = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=15)
        self.query_result.pack(padx=5, pady=5, fill="both", expand=True)
        self.query_result.config(state=tk.DISABLED)

    def create_audit_tab(self):
        """验证审计标签页"""
        frame = ttk.LabelFrame(self.tab_audit, text="验证与审计")
        frame.pack(padx=10, pady=10, fill="both", expand=True)

        # 包含证明验证
        verify_frame = ttk.LabelFrame(frame, text="包含证明验证")
        verify_frame.pack(padx=5, pady=5, fill="x")

        ttk.Label(verify_frame, text="索引：").pack(side=tk.LEFT, padx=5)
        self.verify_index = ttk.Entry(verify_frame, width=10)
        self.verify_index.pack(side=tk.LEFT, padx=5)
        ttk.Button(verify_frame, text="验证", command=self.verify_inclusion).pack(side=tk.LEFT, padx=5)

        # 发布 STH
        ttk.Button(frame, text="发布 STH", command=self.publish_sth).pack(pady=5)

        # 完整审计
        ttk.Button(frame, text="执行完整审计", command=self.run_full_audit).pack(pady=5)

        # 审计结果
        self.audit_result = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=15)
        self.audit_result.pack(padx=5, pady=5, fill="both", expand=True)
        self.audit_result.config(state=tk.DISABLED)

    def create_list_tab(self):
        """日志列表标签页"""
        frame = ttk.LabelFrame(self.tab_list, text="日志列表")
        frame.pack(padx=10, pady=10, fill="both", expand=True)

        # 控制栏
        control_frame = ttk.Frame(frame)
        control_frame.pack(padx=5, pady=5, fill="x")

        ttk.Label(control_frame, text="显示数量：").pack(side=tk.LEFT, padx=5)
        self.list_limit = ttk.Entry(control_frame, width=5)
        self.list_limit.insert(0, "10")
        self.list_limit.pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="刷新列表", command=self.update_log_list).pack(side=tk.LEFT, padx=5)

        # 日志列表
        self.log_list = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=20)
        self.log_list.pack(padx=5, pady=5, fill="both", expand=True)
        self.log_list.config(state=tk.DISABLED)

        # 初始加载列表
        self.update_log_list()

    def update_status(self):
        """更新状态信息"""
        try:
            tree_size = self.server.tree_size
            latest_sth = self.server.get_latest_sth()

            status = f"=== 系统状态 ===\n"
            status += f"存储路径: {self.storage_path}\n"
            status += f"当前树大小: {tree_size}\n"
            status += f"\n"

            if latest_sth:
                status += "=== 最新 STH ===\n"
                status += f"树大小: {latest_sth.tree_size}\n"
                status += f"根哈希: {latest_sth.root_hash.hex()[:40]}...\n"
                status += f"时间戳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(latest_sth.timestamp))}\n"
                status += f"签名长度: {len(latest_sth.signature)} 字节\n"
            else:
                status += "=== 最新 STH ===\n"
                status += "暂无 STH，请先提交日志并发布\n"

            self.status_text.config(state=tk.NORMAL)
            self.status_text.delete(1.0, tk.END)
            self.status_text.insert(tk.END, status)
            self.status_text.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("错误", f"获取状态失败: {str(e)}")

    def submit_log(self):
        """提交日志"""
        data = self.submit_text.get(1.0, tk.END).strip()
        if not data:
            messagebox.showwarning("警告", "请输入日志内容")
            return

        try:
            index = self.server.submit_log(data.encode('utf-8'), int(time.time()))
            self.submit_result.config(text=f"✓ 提交成功！索引: {index}", foreground="green")
            self.submit_text.delete(1.0, tk.END)
            self.update_status()
            self.update_log_list()
        except Exception as e:
            self.submit_result.config(text=f"✗ 提交失败: {str(e)}", foreground="red")

    def query_log(self):
        """查询日志"""
        try:
            index = int(self.query_index.get().strip())
        except ValueError:
            messagebox.showwarning("警告", "请输入有效的索引")
            return

        try:
            entry = self.server.get_log_entry(index)
            if entry is None:
                result = f"索引 {index} 不存在\n"
            else:
                storage_entry = self.server._storage.get_entry(index)
                result = f"=== 日志详情 ===\n"
                result += f"索引: {index}\n"
                result += f"数据: {entry.decode('utf-8')}\n"
                result += f"时间戳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(storage_entry.timestamp))}\n"

            self.query_result.config(state=tk.NORMAL)
            self.query_result.delete(1.0, tk.END)
            self.query_result.insert(tk.END, result)
            self.query_result.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("错误", f"查询失败: {str(e)}")

    def verify_inclusion(self):
        """验证包含证明"""
        try:
            index = int(self.verify_index.get().strip())
        except ValueError:
            messagebox.showwarning("警告", "请输入有效的索引")
            return

        try:
            result = self.auditor.verify_inclusion_proof(index)
            if result.is_pass():
                messagebox.showinfo("验证结果", f"✓ 验证通过！\n{result.message}")
            else:
                messagebox.showwarning("验证结果", f"✗ 验证失败！\n{result.message}")
        except Exception as e:
            messagebox.showerror("错误", f"验证失败: {str(e)}")

    def publish_sth(self):
        """发布 STH"""
        try:
            sth = self.server.force_publish_sth()
            messagebox.showinfo("发布成功", 
                f"STH 发布成功！\n"
                f"树大小: {sth.tree_size}\n"
                f"根哈希: {sth.root_hash.hex()[:40]}...\n"
                f"时间戳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(sth.timestamp))}"
            )
            self.update_status()
        except ValueError as e:
            messagebox.showwarning("警告", str(e))
        except Exception as e:
            messagebox.showerror("错误", f"发布失败: {str(e)}")

    def run_full_audit(self):
        """执行完整审计"""
        try:
            latest_sth = self.server.get_latest_sth()
            report = self.auditor.full_audit(latest_sth)

            result = f"=== 审计报告 ===\n"
            result += f"验证项目: {report.verified_items}\n"
            result += f"通过: {report.passed_items}\n"
            result += f"失败: {report.failed_items}\n"
            result += f"耗时: {report.duration_ms:.2f}ms\n"
            result += f"\n"

            if report.passed_items == report.verified_items:
                result += "✓ 审计通过！\n"
            else:
                result += "✗ 审计失败！\n"

            result += f"\n=== 详细结果 ===\n"
            for res in report.results:
                status = "✓ PASS" if res.is_pass() else "✗ FAIL" if res.is_fail() else "? ERROR"
                item = res.item if res.item else "未知项目"
                result += f"{status} - {item}: {res.message}\n"

            self.audit_result.config(state=tk.NORMAL)
            self.audit_result.delete(1.0, tk.END)
            self.audit_result.insert(tk.END, result)
            self.audit_result.config(state=tk.DISABLED)

            # 显示弹窗提示
            if report.passed_items == report.verified_items:
                messagebox.showinfo("审计完成", "✓ 所有验证项均通过！")
            else:
                messagebox.showwarning("审计完成", f"✗ 部分验证项失败！\n通过: {report.passed_items}/{report.verified_items}")

        except Exception as e:
            messagebox.showerror("错误", f"审计失败: {str(e)}")

    def update_log_list(self):
        """更新日志列表"""
        try:
            limit = int(self.list_limit.get().strip())
        except ValueError:
            limit = 10

        try:
            tree_size = self.server.tree_size
            result = f"=== 日志列表 (共 {tree_size} 条) ===\n"
            result += "-" * 60 + "\n"

            count = 0
            for i in range(tree_size):
                if count >= limit:
                    result += f"... 还有 {tree_size - limit} 条日志\n"
                    break

                entry = self.server.get_log_entry(i)
                if entry:
                    timestamp = self.server._storage.get_entry(i).timestamp
                    timestamp_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))
                    data_preview = entry.decode('utf-8')[:60] + "..." if len(entry) > 60 else entry.decode('utf-8')
                    result += f"[{i:4d}] {timestamp_str}\n      {data_preview}\n"
                count += 1

            if tree_size == 0:
                result += "暂无日志\n"

            self.log_list.config(state=tk.NORMAL)
            self.log_list.delete(1.0, tk.END)
            self.log_list.insert(tk.END, result)
            self.log_list.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("错误", f"加载列表失败: {str(e)}")


def main():
    """主函数"""
    root = tk.Tk()
    app = LogSystemGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
