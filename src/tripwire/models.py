from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class FileChange:
    path: str
    old: Optional[str]  # None: file did not exist before
    new: Optional[str]  # None: file no longer exists


@dataclass(frozen=True)
class Approval:
    lock_id: str
    approver: str
    digest: str  # binds the approval to the exact before/after content


@dataclass(frozen=True)
class Violation:
    lock_id: str
    path: str
    message: str
    digest: str = ""


@dataclass
class Decision:
    violations: List[Violation] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return not self.violations
