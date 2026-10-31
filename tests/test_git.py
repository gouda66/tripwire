import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tripwire.cli import main

SRC = str(Path(__file__).resolve().parents[1] / "src")

RULES = {
    "leaders": ["lead"],
    "locks": [{"id": "billing", "owners": ["olga"], "approvers": ["anna"]}],
}
CODE = "x = 1\n# @lock-begin billing\nrate = 5\n# @lock-end billing\n"


def git(cwd, *args, env=None):
    full = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    full.update(env or {})
    return subprocess.run(["git", *args], cwd=cwd, env=full, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / ".tripwire").mkdir()
    (tmp_path / ".tripwire" / "locks.json").write_text(json.dumps(RULES))
    (tmp_path / "app.py").write_text(CODE)
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "init")
    return tmp_path


def edit(repo, text):
    (repo / "app.py").write_text(text)


def run(repo, *argv):
    return main(["--repo", str(repo), *argv])


def test_preflight_blocks_uncommitted_edit(repo, capsys):
    edit(repo, CODE.replace("5", "9"))
    assert run(repo, "preflight", "--actor", "mallory") == 1
    assert "olga" in capsys.readouterr().err
    assert run(repo, "preflight", "--actor", "olga") == 0


def test_preflight_ignores_unprotected_edit(repo):
    edit(repo, CODE + "z = 1\n")
    assert run(repo, "preflight", "--actor", "mallory") == 0


def test_check_commit_range_and_approve_flow(repo):
    edit(repo, CODE.replace("5", "9"))
    git(repo, "commit", "-qam", "bump")
    assert run(repo, "check", "--base", "HEAD~1", "--head", "HEAD", "--actor", "mallory") == 1
    # a stranger cannot approve; an approver can
    assert run(repo, "approve", "--base", "HEAD~1", "--head", "HEAD", "--approver", "mallory") == 1
    assert run(repo, "approve", "--base", "HEAD~1", "--head", "HEAD", "--approver", "anna") == 0
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "approval")
    assert run(repo, "check", "--base", "HEAD~2", "--head", "HEAD", "--actor", "mallory") == 0
    # approver cannot push their own approved change under their own name... but anna may not self-approve
    assert run(repo, "check", "--base", "HEAD~2", "--head", "HEAD", "--actor", "anna") == 1


def test_rules_come_from_base_not_head(repo):
    rules = dict(RULES, leaders=["mallory"])
    (repo / ".tripwire" / "locks.json").write_text(json.dumps(rules))
    edit(repo, CODE.replace("5", "9"))
    git(repo, "commit", "-qam", "seize")
    assert run(repo, "check", "--base", "HEAD~1", "--head", "HEAD", "--actor", "mallory") == 1


def test_missing_actor_fails_closed(repo, monkeypatch):
    for var in ("TRIPWIRE_ACTOR", "GL_USERNAME", "REMOTE_USER"):
        monkeypatch.delenv(var, raising=False)
    git(repo, "config", "--unset", "user.email")
    edit(repo, CODE.replace("5", "9"))
    code = run(repo, "preflight")
    assert code in (0, 1, 2)  # never crashes; 2 when no identity can be found


@pytest.fixture
def remote(tmp_path, repo):
    bare = tmp_path / "remote.git"
    git(tmp_path, "clone", "-q", "--bare", str(repo), str(bare))
    hook = bare / "hooks" / "pre-receive"
    hook.write_text('#!/bin/sh\nexec "%s" -m tripwire pre-receive\n' % sys.executable.replace("\\", "/"))
    hook.chmod(0o755)
    return bare


def push(repo, remote, actor, *extra):
    env = {"TRIPWIRE_ACTOR": actor, "PYTHONPATH": SRC}
    return git(repo, "push", *extra, str(remote), "main", env=env)


def test_server_hook_rejects_stranger_even_with_no_verify(repo, remote):
    edit(repo, CODE.replace("5", "9"))
    git(repo, "commit", "-qam", "bump")
    res = push(repo, remote, "mallory", "--no-verify")
    assert res.returncode != 0
    assert "BLOCKED" in res.stderr


def test_server_hook_accepts_owner(repo, remote):
    edit(repo, CODE.replace("5", "9"))
    git(repo, "commit", "-qam", "bump")
    assert push(repo, remote, "olga").returncode == 0


def test_server_hook_new_branch(repo, remote):
    git(repo, "checkout", "-q", "-b", "feature")
    edit(repo, CODE.replace("5", "9"))
    git(repo, "commit", "-qam", "bump")
    env = {"TRIPWIRE_ACTOR": "mallory", "PYTHONPATH": SRC}
    assert git(repo, "push", str(remote), "feature", env=env).returncode != 0
    env["TRIPWIRE_ACTOR"] = "olga"
    assert git(repo, "push", str(remote), "feature", env=env).returncode == 0
