"""
日志服务器模块

负责接收日志条目、维护默克尔树与存储引擎,并周期性地发布签名树根 (STH)。
"""

import threading
import time
import os
from dataclasses import dataclass
from typing import Callable, List, Optional

from .crypto import Ed25519Signer, SignedTreeHead
from .merkle import InclusionProof, ConsistencyProof
from .storage import StorageEngine


@dataclass
class ServerConfig:
    """服务器配置。"""
    sth_interval: int = 1000
    sth_timeout: int = 3600
    storage_path: str = "./storage_data"
    enable_encryption: bool = False


class LogServer:
    """日志服务器。"""
    
    _KEY_FILE_NAME = "signing_key.pem"

    def __init__(
        self,
        config: Optional[ServerConfig] = None,
        signing_key: Optional[Ed25519Signer] = None,
    ):
        self._config = config or ServerConfig()

        self._storage = StorageEngine(
            base_path=self._config.storage_path,
            enable_encryption=self._config.enable_encryption,
        )

        if signing_key is None:
            self._signer = self._load_or_generate_signing_key()
        else:
            self._signer = signing_key

        self._last_sth_index = 0
        self._last_sth_time = 0
        self._pending_sth = False
        self._load_sth_state()

        self._audit_callbacks: List[Callable] = []
        self._lock = threading.Lock()
    
    def _load_or_generate_signing_key(self) -> Ed25519Signer:
        """加载已保存的签名密钥，或生成新密钥。"""
        key_path = os.path.join(self._config.storage_path, self._KEY_FILE_NAME)
        
        if os.path.exists(key_path):
            try:
                with open(key_path, 'rb') as f:
                    private_key_bytes = f.read()
                    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
                    return Ed25519Signer(private_key)
            except Exception:
                pass
        
        # 如果加载失败或不存在，生成新密钥并保存
        signer = Ed25519Signer()
        self._save_signing_key(signer)
        return signer
    
    def _save_signing_key(self, signer: Ed25519Signer) -> None:
        """保存签名密钥到文件。"""
        key_path = os.path.join(self._config.storage_path, self._KEY_FILE_NAME)
        os.makedirs(self._config.storage_path, exist_ok=True)
        with open(key_path, 'wb') as f:
            f.write(signer.private_key_bytes)

    # ---------- 初始化 ----------

    def _load_sth_state(self) -> None:
        latest_sth = self._storage.get_latest_sth()
        if latest_sth:
            self._last_sth_index = latest_sth[0]
            self._last_sth_time = latest_sth[2]

    # ---------- 日志写入 ----------

    def submit_log(self, data: bytes, timestamp: Optional[int] = None) -> int:
        with self._lock:
            index = self._storage.append(data, timestamp)
            self._check_and_publish_sth()
            return index

    def submit_log_batch(
        self, entries: List[bytes], timestamp: Optional[int] = None
    ) -> List[int]:
        indices: List[int] = []
        with self._lock:
            for entry in entries:
                indices.append(self._storage.append(entry, timestamp))
            self._check_and_publish_sth()
        return indices

    # ---------- STH 发布 ----------

    def _check_and_publish_sth(self) -> None:
        current_size = self._storage.tree_size
        current_time = int(time.time())

        size_condition = (current_size - self._last_sth_index) >= self._config.sth_interval
        time_condition = (current_time - self._last_sth_time) >= self._config.sth_timeout

        if (size_condition or time_condition or self._pending_sth) and current_size > self._last_sth_index:
            self._publish_sth(current_size)

    def _publish_sth(self, tree_size: int) -> SignedTreeHead:
        root_hash = self._storage.root_hash
        if root_hash is None:
            raise ValueError("树为空,无法发布 STH")

        timestamp = int(time.time())
        signature = self._signer.sign_sth(tree_size, root_hash, timestamp)

        sth = SignedTreeHead(
            tree_size=tree_size,
            root_hash=root_hash,
            timestamp=timestamp,
            signature=signature,
        )

        self._storage.append_sth(tree_size, root_hash, timestamp, signature)
        self._last_sth_index = tree_size
        self._last_sth_time = timestamp
        self._pending_sth = False

        self._notify_audit(sth)
        return sth

    def force_publish_sth(self) -> SignedTreeHead:
        with self._lock:
            tree_size = self._storage.tree_size
            if tree_size == 0:
                raise ValueError("树为空,无法发布 STH")
            return self._publish_sth(tree_size)

    def _notify_audit(self, sth: SignedTreeHead) -> None:
        for callback in self._audit_callbacks:
            try:
                callback(sth)
            except Exception:
                pass

    def register_audit_callback(self, callback: Callable) -> None:
        self._audit_callbacks.append(callback)

    # ---------- 审计查询接口 ----------

    def get_inclusion_proof(self, leaf_index: int) -> InclusionProof:
        return self._storage.merkle_tree.get_inclusion_proof(leaf_index)

    def get_consistency_proof(self, old_tree_size: int) -> ConsistencyProof:
        return self._storage.merkle_tree.get_consistency_proof(old_tree_size)

    def get_log_entry(self, index: int) -> Optional[bytes]:
        return self._storage.get_entry_raw(index)

    def get_latest_sth(self) -> Optional[SignedTreeHead]:
        latest = self._storage.get_latest_sth()
        if latest is None:
            return None
        return SignedTreeHead(
            tree_size=latest[0],
            root_hash=latest[1],
            timestamp=latest[2],
            signature=latest[3],
        )

    def get_all_sth_records(self) -> List[SignedTreeHead]:
        records = self._storage.get_all_sth_records()
        return [
            SignedTreeHead(
                tree_size=r[0], root_hash=r[1], timestamp=r[2], signature=r[3]
            )
            for r in records
        ]

    # ---------- 属性 / 关闭 ----------

    @property
    def tree_size(self) -> int:
        return self._storage.tree_size

    @property
    def root_hash(self) -> Optional[bytes]:
        return self._storage.root_hash

    @property
    def public_key(self) -> bytes:
        return self._signer.public_key_bytes

    def verify_integrity(self) -> bool:
        return self._storage.verify_integrity()

    def close(self) -> None:
        self._storage.close()


class STHPublisher:
    """STH 发布器 - 在独立线程中周期性地强制发布 STH。"""

    def __init__(self, server: LogServer, interval: int = 60):
        self._server = server
        self._interval = interval
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while self._running:
            try:
                self._server.force_publish_sth()
            except ValueError:
                pass
            time.sleep(self._interval)
