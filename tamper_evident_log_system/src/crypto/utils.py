"""
通用密码学工具函数
"""

import secrets
import hmac


def generate_secure_random(size: int) -> bytes:
    """生成安全随机数。"""
    return secrets.token_bytes(size)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """恒定时间比较,抵抗时序攻击。"""
    return hmac.compare_digest(a, b)
