"""Approval providers. Local provider reads .tripwire/approvals.json.

Platform providers (GitHub, GitLab, ...) will implement the same shape:
return a list of Approval for the change being checked.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .config import ConfigError
from .models import Approval


def parse_local(text: Optional[str]) -> List[Approval]:
    if not text or not text.strip():
        return []
    try:
        raw = json.loads(text)
        return [Approval(i["lock"], i["approver"], i["digest"]) for i in raw]
    except (ValueError, KeyError, TypeError) as exc:
        raise ConfigError("invalid approvals file: %s" % exc)


def dump_local(approvals: List[Approval]) -> str:
    return json.dumps(
        [{"lock": a.lock_id, "approver": a.approver, "digest": a.digest} for a in approvals],
        indent=2,
    ) + "\n"
