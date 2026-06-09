"""
存储相关数据结构
"""

from dataclasses import dataclass


@dataclass
class LogEntry:
    """日志条目。"""
    index: int
    timestamp: int
    data: bytes
    offset: int
    length: int


@dataclass
class StorageMetadata:
    """存储元数据。"""
    version: int = 1
    created_at: int = 0
    last_modified: int = 0
    entry_count: int = 0
    encrypted: bool = False
