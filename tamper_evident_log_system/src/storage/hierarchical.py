"""
分层哈希存储

用于持久化不同层级的哈希值,支持快速离线验证。
"""

from typing import List, Optional
from pathlib import Path


class HierarchicalHashStore:
    """分层哈希存储。"""

    def __init__(self, base_path: str):
        self._base_path = Path(base_path)
        self._base_path.mkdir(parents=True, exist_ok=True)

    def store_level(self, level: int, hashes: List[bytes]) -> None:
        level_path = self._base_path / f"level_{level}.bin"
        with open(level_path, 'wb') as f:
            f.write(level.to_bytes(4, 'big'))
            f.write(len(hashes).to_bytes(8, 'big'))
            for h in hashes:
                f.write(h)

    def load_level(self, level: int) -> Optional[List[bytes]]:
        level_path = self._base_path / f"level_{level}.bin"
        if not level_path.exists():
            return None

        with open(level_path, 'rb') as f:
            stored_level = int.from_bytes(f.read(4), 'big')
            if stored_level != level:
                raise ValueError(f"层级不匹配: 期望 {level}, 实际 {stored_level}")
            count = int.from_bytes(f.read(8), 'big')
            hashes: List[bytes] = []
            for _ in range(count):
                hashes.append(f.read(32))
            return hashes

    def get_latest_level(self) -> int:
        levels = []
        for p in self._base_path.glob("level_*.bin"):
            try:
                level = int(p.stem.split('_')[1])
                levels.append(level)
            except (IndexError, ValueError):
                continue
        return max(levels) if levels else -1
