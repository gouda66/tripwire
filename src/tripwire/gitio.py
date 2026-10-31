from __future__ import annotations

import os
import subprocess
from typing import List, Optional

from .models import FileChange

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
ZERO = "0" * 40


class GitError(Exception):
    pass


def git(cwd: str, *args: str, check: bool = True) -> bytes:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True)
    if check and proc.returncode != 0:
        raise GitError("git %s failed: %s" % (" ".join(args), proc.stderr.decode("utf-8", "replace").strip()))
    return proc.stdout if proc.returncode == 0 else b""


def toplevel(cwd: str) -> str:
    return git(cwd, "rev-parse", "--show-toplevel").decode().strip()


class RevSource:
    def __init__(self, cwd: str, rev: str):
        self.cwd, self.rev = cwd, rev

    def read(self, path: str) -> Optional[str]:
        proc = subprocess.run(["git", "show", "%s:%s" % (self.rev, path)], cwd=self.cwd, capture_output=True)
        return proc.stdout.decode("utf-8", "replace") if proc.returncode == 0 else None


class WorktreeSource:
    def __init__(self, root: str):
        self.root = root

    def read(self, path: str) -> Optional[str]:
        full = os.path.join(self.root, path)
        if not os.path.isfile(full):
            return None
        with open(full, "rb") as fh:
            return fh.read().decode("utf-8", "replace")


def _split(raw: bytes) -> List[str]:
    return [p.decode("utf-8") for p in raw.split(b"\0") if p]


def changed_paths(cwd: str, base: str, head: Optional[str]) -> List[str]:
    """head=None is the working tree, head="" is the index (staged changes)."""
    if head == "":
        return _split(git(cwd, "diff", "--cached", "--name-only", "-z", "--no-renames", base))
    if head is not None:
        return _split(git(cwd, "diff", "--name-only", "-z", "--no-renames", base, head))
    tracked = _split(git(cwd, "diff", "--name-only", "-z", "--no-renames", base))
    untracked = _split(git(cwd, "ls-files", "--others", "--exclude-standard", "-z"))
    return sorted(set(tracked) | set(untracked))


def collect_changes(cwd: str, base: str, head: Optional[str]) -> List[FileChange]:
    old_src = RevSource(cwd, base)
    new_src = RevSource(cwd, head) if head is not None else WorktreeSource(cwd)
    return [FileChange(p, old_src.read(p), new_src.read(p)) for p in changed_paths(cwd, base, head)]


def new_branch_base(cwd: str, new: str) -> Optional[str]:
    """Base for a newly created branch: parent of its first not-yet-known commit."""
    out = git(cwd, "rev-list", "--reverse", new, "--not", "--all").decode().split()
    if not out:
        return None
    proc = subprocess.run(["git", "rev-parse", out[0] + "^"], cwd=cwd, capture_output=True)
    return proc.stdout.decode().strip() if proc.returncode == 0 else EMPTY_TREE
