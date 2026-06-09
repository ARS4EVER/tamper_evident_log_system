"""
持续审计器。
"""

import threading
import time
from typing import Callable, Optional

from .models import VerificationResult
from .core import Auditor
from ..crypto import SignedTreeHead


class ContinuousAuditor:
    """持续审计器,定期检查最新 STH 并触发回调。"""

    def __init__(
        self,
        auditor: Auditor,
        check_interval: int = 60,
        anomaly_callback: Optional[Callable[[VerificationResult], None]] = None,
    ):
        self._auditor = auditor
        self._check_interval = check_interval
        self._anomaly_callback = anomaly_callback
        self._running = False
        self._last_sth: Optional[SignedTreeHead] = None
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
                self._check()
            except Exception:
                pass
            time.sleep(self._check_interval)

    def _check(self) -> None:
        latest_sth = self._auditor._storage.get_latest_sth()
        if latest_sth is None:
            return

        sth = SignedTreeHead(
            tree_size=latest_sth[0],
            root_hash=latest_sth[1],
            timestamp=latest_sth[2],
            signature=latest_sth[3],
        )

        if self._last_sth is None or sth.tree_size > self._last_sth.tree_size:
            result = self._auditor.verify_sth_signature(sth)
            if not result.is_pass() and self._anomaly_callback:
                self._anomaly_callback(result)

            if self._last_sth:
                proof = self._auditor._storage.merkle_tree.get_consistency_proof(
                    self._last_sth.tree_size
                )
                cons_result = self._auditor.verify_consistency_proof(proof, sth.root_hash)
                if not cons_result.is_pass() and self._anomaly_callback:
                    self._anomaly_callback(cons_result)

            self._last_sth = sth

    def set_baseline_sth(self, sth: SignedTreeHead) -> None:
        self._last_sth = sth
