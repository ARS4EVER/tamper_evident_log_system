"""存储引擎核心。

整合 AOF 文件、SQLite 索引与默克尔树,提供统一的追加与查询接口。
"""

import json
import time
from pathlib import Path
from typing import List, Optional, Tuple

from .models import LogEntry
from .index import IndexDB
from .aof_writer import AOFWriter
from ..crypto import DomainSeparatedHash
from ..merkle import MerkleTree


class StorageEngine:
    """追加写入存储引擎。"""

    INDEX_EXTENSION = ".idx"

    def __init__(self, base_path: str, enable_encryption: bool = False):
        self._base_path = Path(base_path)
        self._enable_encryption = enable_encryption
        self._base_path.mkdir(parents=True, exist_ok=True)

        self._index_path = self._base_path / f"index{self.INDEX_EXTENSION}"
        self._hash_levels_path = self._base_path / "hash_levels"
        self._hash_levels_path.mkdir(exist_ok=True)

        self._aof_writer = AOFWriter(str(self._base_path))
        self._index_db = IndexDB(str(self._index_path))
        self._merkle_tree = MerkleTree()
        self._load_or_rebuild_tree()

    # ---------- 默克尔树重建/持久化 ----------

    def _load_or_rebuild_tree(self) -> None:
        tree_state_path = self._base_path / "tree_state.json"
        if tree_state_path.exists():
            with open(tree_state_path, 'r') as f:
                state = json.load(f)
                self._merkle_tree = MerkleTree.load_state(state)
        else:
            self._rebuild_tree_from_index()

    def _rebuild_tree_from_index(self) -> None:
        for _, leaf_hash_hex in self._index_db.get_all_leaf_hashes():
            self._merkle_tree.add_leaf_hash(bytes.fromhex(leaf_hash_hex))

    def _save_tree_state(self) -> None:
        state = self._merkle_tree.export_state()
        tree_state_path = self._base_path / "tree_state.json"
        with open(tree_state_path, 'w') as f:
            json.dump(state, f)

    # ---------- 写入 API ----------

    def append(self, data: bytes, timestamp: Optional[int] = None) -> int:
        if timestamp is None:
            timestamp = int(time.time())

        offset = self._aof_writer.append(data)
        length = len(data)

        leaf_hash = DomainSeparatedHash.hash_leaf(data)
        log_index = self._merkle_tree.add_leaf_hash(leaf_hash)

        self._index_db.append_log_index(
            log_index, offset, length, timestamp, leaf_hash.hex(), int(time.time())
        )

        self._aof_writer.increment_entry_count()
        self._save_tree_state()
        self._update_hash_levels_if_needed()

        return log_index

    def _update_hash_levels_if_needed(self) -> None:
        tree_size = self._merkle_tree.tree_size
        depth = (tree_size - 1).bit_length() if tree_size > 0 else 0

        for level in range(depth):
            level_file = self._hash_levels_path / f"level_{level}.hash"
            if level_file.exists():
                continue

            nodes = self._get_level_hashes(level)
            if nodes:
                with open(level_file, 'wb') as f:
                    for node_hash in nodes:
                        f.write(node_hash)

    def _get_level_hashes(self, level: int) -> List[bytes]:
        if level == 0:
            return self._merkle_tree.leaves

        tree_size = self._merkle_tree.tree_size
        if tree_size == 0:
            return []

        current = self._merkle_tree.leaves.copy()
        for _ in range(level):
            next_level = []
            for i in range(0, len(current), 2):
                if i + 1 < len(current):
                    left, right = current[i], current[i + 1]
                else:
                    left = right = current[i]
                next_level.append(DomainSeparatedHash.hash_internal(left, right))
            current = next_level
        return current

    # ---------- 读取 API ----------

    def get_entry(self, index: int) -> Optional[LogEntry]:
        row = self._index_db.get_log_index(index)
        if row is None:
            return None
        log_index, offset, length, timestamp, _ = row

        data = self._aof_writer.read(offset, length)
        if data is None:
            return None

        return LogEntry(
            index=log_index,
            timestamp=timestamp,
            data=data,
            offset=offset,
            length=length,
        )

    def get_entry_raw(self, index: int) -> Optional[bytes]:
        entry = self.get_entry(index)
        return entry.data if entry else None

    def get_entries_slice(self, start: int, end: int) -> List[LogEntry]:
        rows = self._index_db.get_log_range(start, end)
        entries: List[LogEntry] = []
        for row in rows:
            log_index, offset, length, timestamp, _ = row
            data = self._aof_writer.read(offset, length)
            if data is None:
                continue
            entries.append(
                LogEntry(
                    index=log_index,
                    timestamp=timestamp,
                    data=data,
                    offset=offset,
                    length=length,
                )
            )
        return entries

    # ---------- STH ----------

    def get_latest_sth(self) -> Optional[Tuple[int, bytes, int, bytes]]:
        row = self._index_db.get_latest_sth()
        if row is None:
            return None
        tree_size, root_hash_hex, timestamp, signature_hex = row
        return (tree_size, bytes.fromhex(root_hash_hex), timestamp, bytes.fromhex(signature_hex))

    def append_sth(self, tree_size: int, root_hash: bytes, timestamp: int, signature: bytes) -> None:
        self._index_db.append_sth(
            tree_size, root_hash.hex(), timestamp, signature.hex(), int(time.time())
        )

    def get_all_sth_records(self) -> List[Tuple[int, bytes, int, bytes]]:
        rows = self._index_db.get_all_sth()
        return [
            (row[0], bytes.fromhex(row[1]), row[2], bytes.fromhex(row[3])) for row in rows
        ]

    # ---------- 属性与完整性 ----------

    @property
    def merkle_tree(self) -> MerkleTree:
        return self._merkle_tree

    @property
    def tree_size(self) -> int:
        return self._merkle_tree.tree_size

    @property
    def root_hash(self) -> Optional[bytes]:
        return self._merkle_tree.root_hash

    @property
    def entry_count(self) -> int:
        return self._aof_writer.metadata.entry_count

    def verify_integrity(self) -> bool:
        test_tree = MerkleTree()
        for _, leaf_hash_hex in self._index_db.get_all_leaf_hashes():
            test_tree.add_leaf_hash(bytes.fromhex(leaf_hash_hex))
        
        # 如果两棵树都为空，验证通过
        if self._merkle_tree.root_hash is None and test_tree.root_hash is None:
            return True
        
        # 比较根哈希
        return self._merkle_tree.root_hash == test_tree.root_hash
    
    def get_rebuilt_root_hash(self) -> Optional[bytes]:
        """从索引重建树并返回根哈希。"""
        test_tree = MerkleTree()
        for _, leaf_hash_hex in self._index_db.get_all_leaf_hashes():
            test_tree.add_leaf_hash(bytes.fromhex(leaf_hash_hex))
        return test_tree.root_hash

    def close(self) -> None:
        self._save_tree_state()
