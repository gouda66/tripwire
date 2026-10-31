"""Platform-neutral core: diff + actor + rules + approvals -> allow / block."""

from __future__ import annotations

import hashlib
import json
from typing import Iterable, List, Optional

from .blocks import Norm, extract_blocks, normalize
from .config import RULES_PATH, Config, Lock
from .models import Approval, Decision, FileChange, Violation


def change_digest(lock_id: str, path: str, old: Optional[Norm], new: Optional[Norm]) -> str:
    payload = json.dumps(
        [lock_id, path, None if old is None else list(old), None if new is None else list(new)]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _norm(text: Optional[str]) -> Optional[Norm]:
    return None if text is None else normalize(text)


def evaluate(
    config: Config,
    changes: Iterable[FileChange],
    actor: str,
    approvals: Iterable[Approval] = (),
) -> Decision:
    approvals = list(approvals)
    decision = Decision()

    def authorized_for(lock: Lock) -> set:
        return set(lock.owners) | set(config.leaders)

    def check(lock_id: str, lock: Optional[Lock], path: str, what: str, old, new) -> None:
        owners_and_leaders = authorized_for(lock) if lock else set(config.leaders)
        if actor in owners_and_leaders:
            return
        approvers = owners_and_leaders | (set(lock.approvers) if lock else set())
        digest = change_digest(lock_id, path, old, new)
        for a in approvals:
            if (
                a.lock_id == lock_id
                and a.digest == digest
                and a.approver != actor
                and a.approver in approvers
            ):
                return
        ask = ", ".join(sorted(approvers)) or "(nobody configured)"
        decision.violations.append(
            Violation(lock_id, path, "%s '%s' in %s is locked; ask: %s" % (what, lock_id, path, ask), digest)
        )

    for ch in changes:
        old, new = _norm(ch.old), _norm(ch.new)

        if ch.path == RULES_PATH:
            if old != new and actor not in config.leaders:
                decision.violations.append(
                    Violation("<rules>", ch.path, "the rules file may only be changed by leaders: " + ", ".join(sorted(config.leaders)))
                )
            continue

        for lock in config.locks:
            if lock.matches_path(ch.path) and old != new:
                check(lock.id, lock, ch.path, "path lock", old, new)

        old_blocks = extract_blocks(ch.old) if ch.old is not None else {}
        new_blocks = extract_blocks(ch.new) if ch.new is not None else {}
        for block_id in sorted(set(old_blocks) | set(new_blocks)):
            o, n = old_blocks.get(block_id), new_blocks.get(block_id)
            if o != n:
                check(block_id, config.get(block_id), ch.path, "block", o, n)

    return decision
