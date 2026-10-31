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


def _norm(text: Optional[str], mode: str = "ignore") -> Optional[Norm]:
    return None if text is None else normalize(text, mode)


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
        if ch.path == RULES_PATH:
            if _norm(ch.old) != _norm(ch.new) and actor not in config.leaders:
                decision.violations.append(
                    Violation("<rules>", ch.path, "the rules file may only be changed by leaders: " + ", ".join(sorted(config.leaders)))
                )
            continue

        for lock in config.locks:
            if lock.matches_path(ch.path):
                mode = config.mode_for(lock.id)
                old, new = _norm(ch.old, mode), _norm(ch.new, mode)
                if old != new:
                    check(lock.id, lock, ch.path, "path lock", old, new)

        blocks_cache = {}

        def blocks(text: Optional[str], mode: str):
            if text is None:
                return {}
            key = (id(text), mode)
            if key not in blocks_cache:
                blocks_cache[key] = extract_blocks(text, mode)
            return blocks_cache[key]

        block_ids = set(blocks(ch.old, "ignore")) | set(blocks(ch.new, "ignore"))
        for block_id in sorted(block_ids):
            mode = config.mode_for(block_id)
            o, n = blocks(ch.old, mode).get(block_id), blocks(ch.new, mode).get(block_id)
            if o != n:
                check(block_id, config.get(block_id), ch.path, "block", o, n)

    return decision
