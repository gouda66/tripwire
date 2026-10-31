from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional, Tuple

from .approvals import dump_local, parse_local
from .config import APPROVALS_PATH, RULES_PATH, Config, ConfigError, parse_config
from .engine import evaluate
from .gitio import (
    EMPTY_TREE,
    ZERO,
    GitError,
    RevSource,
    WorktreeSource,
    collect_changes,
    git,
    new_branch_base,
    toplevel,
)
from .models import Approval, Decision


def resolve_actor(explicit: Optional[str], root: str) -> str:
    for candidate in (
        explicit,
        os.environ.get("TRIPWIRE_ACTOR"),
        os.environ.get("GL_USERNAME"),
        os.environ.get("REMOTE_USER"),
    ):
        if candidate:
            return candidate
    for key in ("tripwire.actor", "user.email"):
        value = git(root, "config", key, check=False).decode().strip()
        if value:
            return value
    raise ConfigError("cannot determine the acting user; pass --actor or set TRIPWIRE_ACTOR")


def run_check(root: str, base: str, head: Optional[str], actor: str) -> Tuple[Optional[Config], Decision]:
    """Rules are read from `base`, so a change cannot rewrite the rules that judge it."""
    rules = RevSource(root, base).read(RULES_PATH)
    if rules is None:
        return None, Decision()
    config = parse_config(rules)
    head_src = RevSource(root, head) if head is not None else WorktreeSource(root)
    approvals = parse_local(head_src.read(APPROVALS_PATH))
    return config, evaluate(config, collect_changes(root, base, head), actor, approvals)


def report(decision: Decision) -> int:
    if decision.allowed:
        print("tripwire: OK")
        return 0
    print("tripwire: BLOCKED", file=sys.stderr)
    for v in decision.violations:
        print("  - " + v.message, file=sys.stderr)
    return 1


def cmd_check(args, root: str) -> int:
    actor = resolve_actor(args.actor, root)
    _, decision = run_check(root, args.base, args.head, actor)
    return report(decision)


def cmd_preflight(args, root: str) -> int:
    actor = resolve_actor(args.actor, root)
    has_head = git(root, "rev-parse", "--verify", "-q", "HEAD", check=False).strip()
    _, decision = run_check(root, "HEAD" if has_head else EMPTY_TREE, "" if args.staged else None, actor)
    return report(decision)


HOOK_MARK = "# installed by tripwire"
HOOK = """#!/bin/sh
%s
# Local early warning. Bypassable with --no-verify: the server-side check is the real gate.
if command -v tripwire >/dev/null 2>&1; then
  exec tripwire preflight --staged
else
  exec python -m tripwire preflight --staged
fi
""" % HOOK_MARK


def cmd_install_hook(args, root: str) -> int:
    hooks = git(root, "rev-parse", "--git-path", "hooks").decode().strip()
    path = os.path.join(root, hooks, "pre-commit") if not os.path.isabs(hooks) else os.path.join(hooks, "pre-commit")
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            ours = HOOK_MARK in fh.read()
        if not ours and not args.force:
            print("tripwire: %s already exists; use --force to replace it" % path, file=sys.stderr)
            return 1
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(HOOK)
    os.chmod(path, 0o755)
    print("tripwire: installed %s" % path)
    return 0


def cmd_pre_receive(args, root: str) -> int:
    actor = resolve_actor(args.actor, root)
    status = 0
    for line in sys.stdin:
        parts = line.split()
        if len(parts) < 3:
            continue
        old, new, ref = parts[:3]
        if new == ZERO:
            continue
        base = old if old != ZERO else new_branch_base(root, new)
        if base is None:
            continue
        _, decision = run_check(root, base, new, actor)
        if not decision.allowed:
            print("tripwire: push to %s rejected" % ref, file=sys.stderr)
            status = report(decision) or status
    return status


def _pull_number(explicit: Optional[int]) -> int:
    if explicit is not None:
        return explicit
    event = os.environ.get("GITHUB_EVENT_PATH")
    if not event or not os.path.isfile(event):
        raise ConfigError("pull request number unknown; pass --pr")
    with open(event, encoding="utf-8") as fh:
        number = json.load(fh).get("pull_request", {}).get("number")
    if number is None:
        raise ConfigError("not a pull_request event; pass --pr")
    return int(number)


def cmd_github_check(args, root: str) -> int:
    from .github import GitHubClient, check_pull_request

    return report(check_pull_request(root, GitHubClient.from_env(args.github_repo), _pull_number(args.pr)))


def cmd_gitea_check(args, root: str) -> int:
    from .gitea import GiteaClient, check_pull_request

    client = GiteaClient.from_env(args.gitea_repo, args.gitea_url)
    return report(check_pull_request(root, client, _pull_number(args.pr)))


def cmd_gitlab_check(args, root: str) -> int:
    from .gitlab import GitLabClient, check_merge_request

    iid = args.mr or os.environ.get("CI_MERGE_REQUEST_IID")
    if not iid:
        raise ConfigError("merge request number unknown; pass --mr or run in a merge request pipeline")
    return report(check_merge_request(root, GitLabClient.from_env(args.gitlab_project), int(iid)))


def cmd_approve(args, root: str) -> int:
    config, decision = run_check(root, args.base, args.head, actor="")
    if config is None:
        print("tripwire: no rules file at base", file=sys.stderr)
        return 2
    if args.approver not in config.everyone():
        print("tripwire: %s is not an owner, approver or leader" % args.approver, file=sys.stderr)
        return 1
    path = os.path.join(root, APPROVALS_PATH)
    existing: List[Approval] = []
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            existing = parse_local(fh.read())
    added = 0
    for v in decision.violations:
        if v.digest and (args.lock is None or v.lock_id == args.lock):
            lock = config.get(v.lock_id)
            allowed = set(config.leaders) | (set(lock.owners) | set(lock.approvers) if lock else set())
            if args.approver in allowed:
                existing.append(Approval(v.lock_id, args.approver, v.digest))
                added += 1
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(dump_local(existing))
    print("tripwire: recorded %d approval(s) in %s" % (added, APPROVALS_PATH))
    return 0 if added else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tripwire")
    p.add_argument("--repo", default=".", help="path inside the repository")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("check", help="check base..head (head defaults to the working tree)")
    c.add_argument("--base", required=True)
    c.add_argument("--head")
    c.add_argument("--actor")
    c.set_defaults(func=cmd_check)

    f = sub.add_parser("preflight", help="check uncommitted changes against HEAD")
    f.add_argument("--actor")
    f.add_argument("--staged", action="store_true", help="check only staged changes (for pre-commit)")
    f.set_defaults(func=cmd_preflight)

    h = sub.add_parser("install-hook", help="install a local pre-commit hook")
    h.add_argument("--force", action="store_true", help="replace an existing pre-commit hook")
    h.set_defaults(func=cmd_install_hook)

    r = sub.add_parser("pre-receive", help="server hook: read ref updates from stdin")
    r.add_argument("--actor")
    r.set_defaults(func=cmd_pre_receive)

    g = sub.add_parser("github-check", help="check a GitHub pull request using its reviews")
    g.add_argument("--pr", type=int, help="PR number (default: from GITHUB_EVENT_PATH)")
    g.add_argument("--github-repo", help="owner/name (default: GITHUB_REPOSITORY)")
    g.set_defaults(func=cmd_github_check)

    gt = sub.add_parser("gitea-check", help="check a Gitea/Forgejo pull request using its reviews")
    gt.add_argument("--pr", type=int, help="PR number (default: from GITHUB_EVENT_PATH)")
    gt.add_argument("--gitea-repo", help="owner/name (default: GITHUB_REPOSITORY)")
    gt.add_argument("--gitea-url", help="API base, e.g. https://git.example.com/api/v1")
    gt.set_defaults(func=cmd_gitea_check)

    gl = sub.add_parser("gitlab-check", help="check a GitLab merge request using its approvals")
    gl.add_argument("--mr", type=int, help="MR iid (default: CI_MERGE_REQUEST_IID)")
    gl.add_argument("--gitlab-project", help="project id or path (default: CI_PROJECT_ID)")
    gl.set_defaults(func=cmd_gitlab_check)

    a = sub.add_parser("approve", help="record an approval for the pending change")
    a.add_argument("--base", required=True)
    a.add_argument("--head")
    a.add_argument("--approver", required=True)
    a.add_argument("--lock", help="only approve this lock id")
    a.set_defaults(func=cmd_approve)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = toplevel(args.repo) if args.command != "pre-receive" else os.path.abspath(args.repo)
        return args.func(args, root)
    except (ConfigError, GitError) as exc:
        print("tripwire: error: %s" % exc, file=sys.stderr)
        return 2
