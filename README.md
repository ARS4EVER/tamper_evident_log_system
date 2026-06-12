# 防篡改审计日志系统 (Tamper-Evident Audit Log System)

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#license)

一个使用密码学技术（Merkle树、签名树根等）实现的审计日志系统，确保日志的完整性、不可否认性和可审计性。该系统能够防止日志被篡改，并支持完整的审计验证。

## 🎯 核心功能

- **日志管理**: 提交、查询和管理审计日志
- **完整性保护**: 使用Merkle树确保日志无法被篡改
- **签名证明**: 发布签名树根(STH)用于日志验证
- **包含证明**: 证明特定日志条目存在于日志树中
- **一致性证明**: 验证日志树的一致性增长
- **完整审计**: 执行综合审计报告验证
- **GUI界面**: 提供用户友好的图形界面
- **命令行工具**: 纯CLI模式用于自动化和脚本

## 📋 项目结构

```
tamper_evident_log_system/
├── cli_manager.py          # 命令行管理工具
├── gui_manager.py          # 图形界面管理工具
├── demo.py                 # 演示程序
├── requirements.txt        # Python依赖
├── src/                    # 核心源代码
│   ├── server.py          # 日志服务器
│   ├── auditor.py         # 审计器
│   ├── storage.py         # 存储模块
│   ├── merkle.py          # Merkle树实现
│   ├── crypto/            # 密码学模块
│   │   ├── sth.py         # 签名树根
│   │   ├── crypto.py      # 加密算法
│   │   └── ...
│   └── ...
├── web_storage/           # Web存储模块
└── ...
```

## 🚀 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

### 基本使用

#### 1. 运行演示程序

了解系统的完整工作流程：

```bash
python demo.py
```

演示将展示：
- 日志服务器初始化
- 日志条目提交
- STH发布
- 包含和一致性证明验证
- 完整审计执行
- 安全特性验证
- 性能测试

#### 2. 交互式命令行工具

启动命令行管理工具进行交互式操作：

```bash
python cli_manager.py --interactive
```

可用命令：

| 命令 | 描述 |
|------|------|
| `status` | 显示系统状态 |
| `submit <数据>` | 提交日志 |
| `query <索引>` | 查询日志条目 |
| `verify <索引>` | 验证包含证明 |
| `publish` | 发布签名树根(STH) |
| `audit` | 执行完整审计 |
| `list [起始] [数量]` | 列出日志 |
| `help` | 显示帮助信息 |
| `exit` | 退出程序 |

示例：

```bash
# 提交日志
日志系统> submit User login: admin@example.com
[OK] 日志已提交，索引: 0

# 查询日志
日志系统> query 0
[INFO] 索引: 0
[INFO] 数据: User login: admin@example.com
[INFO] 时间戳: 1623456789

# 发布STH
日志系统> publish
[OK] STH 发布成功
[INFO] 树大小: 10
[INFO] 根哈希: a1b2c3d4...

# 验证日志
日志系统> verify 0
[OK] 包含证明验证通过

# 执行完整审计
日志系统> audit
[OK] 审计通过！
[INFO] 验证项目: 5
[INFO] 通过: 5
[INFO] 失败: 0
```

#### 3. 图形界面工具

启动图形界面进行可视化操作：

```bash
python gui_manager.py
```

图形界面提供：
- 日志提交和查询界面
- 系统状态实时显示
- STH发布管理
- 审计结果可视化
- 日志列表展示

## 🔒 核心技术

### Merkle树

系统使用Merkle树结构组织日志，每条日志都被哈希化后存储在树中：

- **叶子节点**: 单条日志的哈希值
- **内部节点**: 由两个子节点的哈希组合而成
- **根节点**: 整个日志树的代表

### 签名树根 (Signed Tree Head - STH)

定期发布的签名证明，包含：
- 树大小（日志条数）
- 根哈希
- 时间戳
- 服务器签名

### 包含证明

用于证明特定日志条目在树中的位置，验证流程：

1. 获取日志条目和其包含证明
2. 使用证明中的哈希值重新计算根哈希
3. 与已知的STH根哈希对比

### 一致性证明

验证日志树的单调增长，确保：
- 新的树是旧树的扩展
- 没有日志被删除或修改
- 新发布的STH与旧STH保持一致

## 📊 工作流程

```
┌─────────────────────────────────────────────────────┐
│                  日志提交流程                        │
└─────────────────────────────────────────────────────┘
         ↓
    提交日志条目
         ↓
  存储并计算哈希
         ↓
  更新Merkle树
         ↓
    检查发布间隔
         ↓
  [定期] 发布STH
         ↓
┌─────────────────────────────────────────────────────┐
│                  审计验证流程                        │
└─────────────────────────────────────────────────────┘
         ↓
   获取STH和日志
         ↓
   验证STH签名
         ↓
 获取包含/一致性证明
         ↓
  使用证明验证日志
         ↓
  返回审计结果
```

## 🔧 配置参数

在 `cli_manager.py` 中可以配置：

```python
config = ServerConfig(
    storage_path="./data",        # 存储路径
    sth_interval=10,              # 每N条日志发布STH
    sth_timeout=3600,             # 或每N秒发布一次
    enable_encryption=False       # 是否启用加密
)
```

## 📈 性能指标

系统性能取决于日志数量和操作类型：

- **日志提交**: 毫秒级
- **查询验证**: 对数时间复杂度 O(log n)
- **STH发布**: 与日志数量相关
- **完整审计**: 毫秒到秒级

详见 `demo.py` 中的性能测试部分。

## 🛡️ 安全特性

### 防篡改

- ✅ 检测单个日志的修改
- ✅ 检测日志的删除或重排序
- ✅ 检测根哈希被篡改
- ✅ 检测签名被伪造

### 签名验证

使用Ed25519算法验证所有STH的真实性。

### 审计追踪

完整的操作记录：
- 日志提交时间戳
- STH发布记录
- 审计验证结果

## 📝 使用示例

### Python API使用

```python
from src import LogServer, ServerConfig, Auditor

# 初始化服务器
config = ServerConfig(storage_path="./data")
server = LogServer(config)

# 提交日志
log_data = b"User login: alice@example.com"
index = server.submit_log(log_data)

# 发布STH
sth = server.force_publish_sth()

# 获取包含证明
proof = server.get_inclusion_proof(index)

# 初始化审计器
auditor = Auditor(server.public_key, "./data")

# 验证STH签名
result = auditor.verify_sth_signature(sth)

# 执行完整审计
report = auditor.full_audit(sth)

print(f"审计结果: 通过 {report.passed_items}/{report.verified_items}")

# 关闭
auditor.close()
server.close()
```

## 🔍 故障排除

### 问题: "索引不存在"

**原因**: 查询的日志索引超出范围

**解决**: 先运行 `status` 命令查看当前树大小

### 问题: "验证失败"

**原因**: 数据被篡改或STH不匹配

**解决**: 运行 `audit` 命令执行完整审计

### 问题: 性能不佳

**原因**: 日志数量过大或磁盘IO缓慢

**解决**: 增加 `sth_interval` 参数以减少STH发布频率

## 📚 学习资源

- [Merkle树概念](https://en.wikipedia.org/wiki/Merkle_tree)
- [证书透明度(Certificate Transparency)](https://tools.ietf.org/html/rfc6962)
- [Ed25519签名方案](https://ed25519.cr.yp.to/)

## 🤝 贡献

欢迎提交问题报告和改进建议！

## 📄 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

## 📞 联系方式

如有问题或建议，请通过以下方式联系：

- 提交 Issue
- 发送 Pull Request
- 联系项目维护者

## 🎓 项目信息

- **语言**: Python 3.7+
- **依赖**: cryptography >= 41.0.0
- **创建时间**: 2026年
- **维护者**: ARS4EVER

---

**更新于**: 2026-06-12

**版本**: 1.0.0

祝您使用愉快！🚀
