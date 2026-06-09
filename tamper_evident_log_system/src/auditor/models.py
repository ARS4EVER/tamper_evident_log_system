"""
审计数据类型定义。
"""

from enum import Enum
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


class AuditResult(Enum):
    """审计结果。"""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


@dataclass
class VerificationResult:
    """验证结果。"""

    result: AuditResult
    message: str
    details: Optional[Dict[str, Any]] = None
    item: Optional[str] = None

    def is_pass(self) -> bool:
        return self.result == AuditResult.PASS

    def is_fail(self) -> bool:
        return self.result == AuditResult.FAIL


@dataclass
class AuditReport:
    """审计报告。"""

    timestamp: int
    verified_items: int
    passed_items: int
    failed_items: int
    results: List[VerificationResult]
    duration_ms: float
