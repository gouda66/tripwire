import json
import os
import subprocess

import pytest

from tripwire.gitlab import GitLabClient, approved_usernames, check_merge_request

RULES = {
    "leaders": ["lead"],
    "locks": [{"id": "billing", "owners": ["olga"], "approvers": ["Anna"]}],
}
CODE = "x = 1\n# @lock-begin billing\nrate = 5\n# @lock-end billing\n"


def git(cwd, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    return subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True).stdout.strip()


class FakeClient:
    def __init__(self, base, head, author, approvers):
        self.mr = {"sha": head, "author": {"username": author}, "target_branch": "main",
                   "diff_refs": {"start_sha": "stale-sha", "base_sha": "stale-sha", "head_sha": head}}
        self.approvals = {"approved_by": [{"user": {"username": u}} for u in approvers]}
        self.tip = base

    def get_branch_sha(self, branch):
        return self.tip

    def get_merge_request(self, iid):
        return self.mr

    def get_approvals(self, iid):
        return self.approvals


@pytest.fixture
def mr(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / ".tripwire").mkdir()
    (tmp_path / ".tripwire" / "locks.json").write_text(json.dumps(RULES))
    (tmp_path / "app.py").write_text(CODE)
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "init")
    base = git(tmp_path, "rev-parse", "HEAD")
    git(tmp_path, "checkout", "-q", "-b", "feature")
    (tmp_path / "app.py").write_text(CODE.replace("5", "9"))
    git(tmp_path, "commit", "-qam", "bump")
    return tmp_path, base, git(tmp_path, "rev-parse", "HEAD")


def test_approved_usernames():
    assert approved_usernames({"approved_by": [{"user": {"username": "a"}}, {"user": None}]}) == {"a"}
    assert approved_usernames({}) == set()


def test_mr_without_approval_blocked(mr):
    root, base, head = mr
    assert not check_merge_request(root, FakeClient(base, head, "mallory", []), 1).allowed


def test_mr_with_approver_allowed(mr):
    root, base, head = mr
    assert check_merge_request(root, FakeClient(base, head, "mallory", ["anna"]), 1).allowed


def test_approval_from_stranger_blocked(mr):
    root, base, head = mr
    assert not check_merge_request(root, FakeClient(base, head, "mallory", ["bob"]), 1).allowed


def test_author_cannot_approve_own_mr(mr):
    root, base, head = mr
    assert not check_merge_request(root, FakeClient(base, head, "anna", ["anna"]), 1).allowed


def test_owner_authored_mr_needs_no_approval(mr):
    root, base, head = mr
    assert check_merge_request(root, FakeClient(base, head, "olga", []), 1).allowed


def test_rules_change_cannot_be_approved(mr):
    root, base, _ = mr
    (root / ".tripwire" / "locks.json").write_text(json.dumps(dict(RULES, leaders=["mallory"])))
    git(root, "commit", "-qam", "seize")
    head = git(root, "rev-parse", "HEAD")
    assert not check_merge_request(root, FakeClient(base, head, "mallory", ["lead"]), 1).allowed


def test_client_urls_and_auth_headers():
    seen = []

    def fetch(url):
        seen.append(url)
        return b"{}", ""

    GitLabClient("group/proj", "t", "https://gl.example/api/v4", fetch=fetch).get_approvals(7)
    assert seen == ["https://gl.example/api/v4/projects/group%2Fproj/merge_requests/7/approvals"]
