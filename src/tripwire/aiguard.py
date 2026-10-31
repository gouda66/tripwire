"""Guard for AI coding agents (Claude Code PreToolUse hook).

The agent acts as its own identity (TRIPWIRE_AI_ACTOR, default "ai-agent"). An
edit to a protected block is refused before it reaches the disk; the refusal is
recorded as a pending request. A human approves it from a real terminal with
`tripwire grant`, after which the agent can retry the exact same edit.
"""

from __future__ import annotations

import json
import os
import time
from typing import List, Optional

from .approvals import parse_local
from .config import APPROVALS_PATH, RULES_PATH, parse_config
from .engine import evaluate
from .gitio import RevSource, WorktreeSource, git
from .models import Decision, FileChange, Violation

DEFAULT_AI_ACTOR = "ai-agent"
# Best-effort: stop the agent from approving itself or rewriting the rules via the shell.
GUARDED_BASH = (
    "tripwire grant",
    ".tripwire/approvals.json",
    ".tripwire\\approvals.json",
    ".tripwire/locks.json",
    ".tripwire\\locks.json",
)


def ai_actor() -> str:
    return os.environ.get("TRIPWIRE_AI_ACTOR") or DEFAULT_AI_ACTOR


def _apply_edit(content: str, old: str, new: str, replace_all: bool) -> Optional[str]:
    if old not in content:
        return None  # the tool itself will fail; nothing to guard
    if replace_all:
        return content.replace(old, new)
    if content.count(old) != 1:
        return None
    return content.replace(old, new, 1)


def proposed_changes(root: str, tool: str, tool_input: dict, cwd: str) -> List[FileChange]:
    path = tool_input.get("file_path")
    if not path:
        return []
    full = path if os.path.isabs(path) else os.path.join(cwd, path)
    try:
        rel = os.path.relpath(full, root).replace(os.sep, "/")
    except ValueError:  # different drive
        return []
    if rel.startswith(".."):
        return []
    old = WorktreeSource(root).read(rel)
    if tool == "Write":
        return [FileChange(rel, old, tool_input.get("content", ""))]
    if old is None:
        return []
    if tool == "Edit":
        edits = [tool_input]
    elif tool == "MultiEdit":
        edits = tool_input.get("edits") or []
    else:
        return []
    new = old.replace("\r\n", "\n")  # match regardless of the file's line endings
    for e in edits:
        new = _apply_edit(
            new,
            e.get("old_string", "").replace("\r\n", "\n"),
            e.get("new_string", "").replace("\r\n", "\n"),
            bool(e.get("replace_all")),
        )
        if new is None:
            return []
    return [FileChange(rel, old, new)]


def pending_path(root: str) -> str:
    git_dir = git(root, "rev-parse", "--absolute-git-dir").decode().strip()
    return os.path.join(git_dir, "tripwire", "pending.json")


def load_pending(root: str) -> List[dict]:
    path = pending_path(root)
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save_pending(root: str, items: List[dict]) -> None:
    path = pending_path(root)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(items, fh, indent=2)


def _record_pending(root: str, decision: Decision) -> None:
    items = load_pending(root)
    known = {i["digest"] for i in items}
    for v in decision.violations:
        if v.digest and v.digest not in known:
            items.append({"digest": v.digest, "lock": v.lock_id, "path": v.path, "message": v.message, "time": int(time.time())})
    save_pending(root, items)


def check_tool_call(root: str, payload: dict) -> Decision:
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}

    if tool == "Bash":
        command = tool_input.get("command", "")
        if any(token in command for token in GUARDED_BASH):
            return Decision([Violation("<bash>", "", "shell commands may not touch tripwire approvals or rules")])
        return Decision()

    changes = proposed_changes(root, tool, tool_input, payload.get("cwd") or root)
    if not changes:
        return Decision()
    if changes[0].path == APPROVALS_PATH:
        return Decision([Violation("<approvals>", APPROVALS_PATH, "the agent may not edit the approvals file; a human uses `tripwire grant`")])

    rules = RevSource(root, "HEAD").read(RULES_PATH)  # rules always come from the committed version
    if rules is None:
        return Decision()
    config = parse_config(rules)
    approvals = parse_local(WorktreeSource(root).read(APPROVALS_PATH))
    decision = evaluate(config, changes, ai_actor(), approvals)
    if not decision.allowed:
        _record_pending(root, decision)
    return decision
