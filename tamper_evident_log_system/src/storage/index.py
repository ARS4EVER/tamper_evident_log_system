"""SQLite 索引数据库。

管理日志条目偏移量索引与 STH 记录表。
"""

import sqlite3
from pathlib import Path
from typing import List, Optional, Tuple


class IndexDB:
    """SQLite 索引数据库。"""

    def __init__(self, index_path: str):
        self._index_path = Path(index_path)
        self._conn: Optional[sqlite3.Connection] = None
        self._cursor: Optional[sqlite3.Cursor] = None
        self._init_db()

    # ---------- 连接管理 ----------

    def _connect(self) -> None:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._index_path), check_same_thread=False)
            self._conn.row_factory = None
            self._cursor = self._conn.cursor()

    def _commit(self) -> None:
        if self._conn is not None:
            self._conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.commit()
            except sqlite3.Error:
                pass
            self._conn.close()
            self._conn = None
            self._cursor = None

    # ---------- 初始化 ----------

    def _init_db(self) -> None:
        self._connect()
        assert self._cursor is not None
        self._cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS log_index (
                log_index INTEGER PRIMARY KEY,
                offset INTEGER NOT NULL,
                length INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                leaf_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
        """
        )
        self._cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sth_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tree_size INTEGER NOT NULL,
                root_hash TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                signature TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
        """
        )
        self._commit()

    # ---------- 日志条目索引 ----------

    def append_log_index(
        self,
        log_index: int,
        offset: int,
        length: int,
        timestamp: int,
        leaf_hash_hex: str,
        created_at: int,
    ) -> None:
        self._connect()
        assert self._cursor is not None
        self._cursor.execute(
            "INSERT INTO log_index (log_index, offset, length, timestamp, leaf_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (log_index, offset, length, timestamp, leaf_hash_hex, created_at),
        )
        self._commit()

    def get_log_index(self, log_index: int) -> Optional[Tuple[int, int, int, int, str]]:
        """返回 (log_index, offset, length, timestamp, leaf_hash_hex) 或 None。"""
        self._connect()
        assert self._cursor is not None
        self._cursor.execute(
            "SELECT log_index, offset, length, timestamp, leaf_hash FROM log_index WHERE log_index = ?",
            (log_index,),
        )
        return self._cursor.fetchone()

    def get_log_range(self, start: int, end: int) -> List[Tuple[int, int, int, int, str]]:
        """返回 [start, end) 范围内的所有日志索引记录。"""
        self._connect()
        assert self._cursor is not None
        self._cursor.execute(
            "SELECT log_index, offset, length, timestamp, leaf_hash FROM log_index WHERE log_index >= ? AND log_index < ? ORDER BY log_index",
            (start, end),
        )
        return self._cursor.fetchall()

    def get_all_leaf_hashes(self) -> List[Tuple[int, str]]:
        """返回所有 (log_index, leaf_hash_hex) 列表,按 log_index 排序。"""
        self._connect()
        assert self._cursor is not None
        self._cursor.execute("SELECT log_index, leaf_hash FROM log_index ORDER BY log_index")
        return self._cursor.fetchall()

    # ---------- STH 记录 ----------

    def append_sth(
        self,
        tree_size: int,
        root_hash_hex: str,
        timestamp: int,
        signature_hex: str,
        created_at: int,
    ) -> None:
        self._connect()
        assert self._cursor is not None
        self._cursor.execute(
            "INSERT INTO sth_records (tree_size, root_hash, timestamp, signature, created_at) VALUES (?, ?, ?, ?, ?)",
            (tree_size, root_hash_hex, timestamp, signature_hex, created_at),
        )
        self._commit()

    def get_latest_sth(self) -> Optional[Tuple[int, str, int, str]]:
        """返回 (tree_size, root_hash_hex, timestamp, signature_hex) 或 None。"""
        self._connect()
        assert self._cursor is not None
        self._cursor.execute(
            "SELECT tree_size, root_hash, timestamp, signature FROM sth_records ORDER BY id DESC LIMIT 1"
        )
        return self._cursor.fetchone()

    def get_all_sth(self) -> List[Tuple[int, str, int, str]]:
        self._connect()
        assert self._cursor is not None
        self._cursor.execute(
            "SELECT tree_size, root_hash, timestamp, signature FROM sth_records ORDER BY id"
        )
        return self._cursor.fetchall()
