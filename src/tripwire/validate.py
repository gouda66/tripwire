"""`tripwire validate`: sanity-check the rules file against the repository."""

from __future__ import annotations

import fnmatch
from typing import List, Set, Tuple

from .blocks import BEGIN, END
from .config import ConfigError, parse_config
from .gitio import WorktreeSource, git

MAX_BYTES = 1_000_000


def _tracked(root: str) -> List[str]:
    return [p.decode("utf-8") for p in git(root, "ls-files", "-z").split(b"\0") if p]


def validate(root: str, rules_text: str) -> Tuple[List[str], List[str]]:
    """Return (errors, warnings)."""
    errors: List[str] = []
    warnings: List[str] = []
    try:
        config = parse_config(rules_text)
    except ConfigError as exc:
        return [str(exc)], warnings

    if not config.leaders:
        warnings.append("no leaders: nobody will be able to change the rules file")
    refs = config.team_refs()
    if refs:
        warnings.append(
            "platform team references (%s) are only resolved by the GitHub adapter; "
            "elsewhere they never match anybody" % ", ".join(sorted(refs))
        )

    src = WorktreeSource(root)
    marker_ids: Set[str] = set()
    paths = _tracked(root)
    for path in paths:
        text = src.read(path)
        if text is None or len(text) > MAX_BYTES or "\0" in text:
            continue
        open_ids: List[str] = []
        for line in text.splitlines():
            b, e = BEGIN.search(line), END.search(line)
            if b:
                marker_ids.add(b.group(1))
                open_ids.append(b.group(1))
            elif e:
                if e.group(1) in open_ids:
                    open_ids.remove(e.group(1))
                else:
                    warnings.append("%s: @lock-end %s without a matching @lock-begin" % (path, e.group(1)))
        for block_id in open_ids:
            warnings.append("%s: @lock-begin %s is never closed (it protects the rest of the file)" % (path, block_id))

    known = {lock.id for lock in config.locks}
    for block_id in sorted(marker_ids - known):
        warnings.append("block '%s' has markers but no lock: only leaders may change it" % block_id)
    for lock in config.locks:
        if not lock.owners and not lock.approvers:
            warnings.append("lock '%s' has no owners or approvers: only leaders can change it" % lock.id)
        matched = any(lock.matches_path(p) for p in paths)
        if lock.paths and not matched:
            warnings.append("lock '%s': none of its paths match a tracked file" % lock.id)
        if not lock.paths and lock.id not in marker_ids:
            warnings.append("lock '%s' has no paths and no @lock-begin markers in the repository" % lock.id)
    return errors, warnings
