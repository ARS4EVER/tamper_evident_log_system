"""AOF (Append-Only File) 写入器。

负责原始日志数据的追加写入和元数据管理。
"""

import json
import time
from pathlib import Path
from typing import Optional

from .models import StorageMetadata


class AOFWriter:
    """仅追加文件写入器。

    管理原始日志文件和元数据文件。
    """

    AOF_EXTENSION = ".aof"
    META_EXTENSION = ".meta"

    def __init__(self, base_path: str):
        self._base_path = Path(base_path)
        self._base_path.mkdir(parents=True, exist_ok=True)
        self._aof_path = self._base_path / f"raw_logs{self.AOF_EXTENSION}"
        self._meta_path = self._base_path / f"metadata{self.META_EXTENSION}"
        if not self._aof_path.exists():
            self._aof_path.touch()
        self._metadata = self._load_metadata()

    # ---------- 元数据管理 ----------

    def _load_metadata(self) -> StorageMetadata:
        if self._meta_path.exists():
            with open(self._meta_path, "r") as f:
                data = json.load(f)
                return StorageMetadata(**data)
        meta = StorageMetadata(
            created_at=int(time.time()), last_modified=int(time.time())
        )
        self._save_metadata(meta)
        return meta

    def _save_metadata(self, meta: StorageMetadata) -> None:
        meta.last_modified = int(time.time())
        with open(self._meta_path, "w") as f:
            json.dump(
                {
                    "version": meta.version,
                    "created_at": meta.created_at,
                    "last_modified": meta.last_modified,
                    "entry_count": meta.entry_count,
                    "encrypted": meta.encrypted,
                },
                f,
            )

    @property
    def metadata(self) -> StorageMetadata:
        return self._metadata

    def increment_entry_count(self) -> None:
        self._metadata.entry_count += 1
        self._save_metadata(self._metadata)

    # ---------- 写入操作 ----------

    def append(self, data: bytes) -> int:
        """追加数据到 AOF 文件。

        Args:
            data: 要写入的原始字节数据。

        Returns:
            写入位置的偏移量。
        """
        with open(self._aof_path, "ab") as f:
            offset = f.tell()
            f.write(data)
        return offset

    # ---------- 读取操作 ----------

    def read(self, offset: int, length: int) -> Optional[bytes]:
        """从 AOF 文件读取指定范围的数据。

        Args:
            offset: 数据偏移量。
            length: 数据长度。

        Returns:
            读取到的字节数据，或 None（读取失败时）。
        """
        try:
            with open(self._aof_path, "rb") as f:
                f.seek(offset)
                return f.read(length)
        except (OSError, IOError):
            return None

    @property
    def aof_path(self) -> Path:
        return self._aof_path

    @property
    def file_size(self) -> int:
        return self._aof_path.stat().st_size if self._aof_path.exists() else 0
