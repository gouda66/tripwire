"""Platform-neutral review check shared by the GitHub and GitLab adapters."""

from __future__ import annotations

from typing import Callable, Dict, Iterable, Optional, Sequence

from .config import RULES_PATH, parse_config
from .engine import evaluate
from .gitio import RevSource, collect_changes, git
from .models import Approval, Decision


def check_review(
    root: str,
    target_sha: str,
    head_sha: str,
    author: str,
    approvers: Iterable[str],
    resolve_team: Optional[Callable[[str], Sequence[str]]] = None,
) -> Decision:
    """Evaluate a pull/merge request.

    Rules come from the target branch tip (`target_sha`), the diff from the
    merge base to `head_sha`. `approvers` are platform user names whose approval
    applies to the current head; names are matched to the rules case-insensitively.
    """
    rules = RevSource(root, target_sha).read(RULES_PATH)
    if rules is None:
        return Decision()
    config = parse_config(rules)
    if resolve_team is not None and config.team_refs():
        config = config.expand_teams(resolve_team)
    names: Dict[str, str] = {name.lower(): name for name in config.everyone()}
    actor = names.get(author.lower(), author)

    merge_base = git(root, "merge-base", target_sha, head_sha).decode().strip()
    changes = collect_changes(root, merge_base, head_sha)

    first = evaluate(config, changes, actor, [])
    reviewers = sorted({names[u.lower()] for u in approvers if u.lower() in names})
    approvals = [Approval(v.lock_id, who, v.digest) for v in first.violations if v.digest for who in reviewers]
    return evaluate(config, changes, actor, approvals)
