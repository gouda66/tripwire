import json
import os
import subprocess

import pytest

from tripwire.github import GitHubClient, approved_logins, check_pull_request

RULES = {
    "leaders": ["lead"],
    "locks": [{"id": "billing", "owners": ["olga"], "approvers": ["Anna"]}],
}
CODE = "x = 1\n# @lock-begin billing\nrate = 5\n# @lock-end billing\n"


def git(cwd, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    return subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True).stdout.strip()


class FakeClient:
    def __init__(self, base, head, author, reviews):
        self.pr = {"base": {"sha": "stale-sha", "ref": "main"}, "head": {"sha": head}, "user": {"login": author}}
        self.reviews = reviews
        self.tip = base

    def get_branch_sha(self, branch):
        return self.tip

    def get_pull(self, number):
        return self.pr

    def get_reviews(self, number):
        return self.reviews


def review(user, state, sha):
    return {"user": {"login": user}, "state": state, "commit_id": sha}


@pytest.fixture
def pr(tmp_path):
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
    head = git(tmp_path, "rev-parse", "HEAD")
    return tmp_path, base, head


def test_latest_review_per_user_and_head_only():
    reviews = [
        review("a", "APPROVED", "h1"),
        review("a", "CHANGES_REQUESTED", "h1"),
        review("b", "APPROVED", "old"),
        review("c", "APPROVED", "h1"),
        review("c", "COMMENTED", "h1"),
        review("d", "APPROVED", "h1"),
        review("d", "DISMISSED", "h1"),
    ]
    assert approved_logins(reviews, "h1") == {"c"}


def test_pr_without_approval_blocked(pr):
    root, base, head = pr
    assert not check_pull_request(root, FakeClient(base, head, "mallory", []), 1).allowed


def test_pr_with_approver_review_allowed_case_insensitive(pr):
    root, base, head = pr
    client = FakeClient(base, head, "mallory", [review("anna", "APPROVED", head)])
    assert check_pull_request(root, client, 1).allowed


def test_stale_approval_after_new_push_blocked(pr):
    root, base, head = pr
    client = FakeClient(base, head, "mallory", [review("anna", "APPROVED", "older-sha")])
    assert not check_pull_request(root, client, 1).allowed


def test_approval_from_stranger_blocked(pr):
    root, base, head = pr
    client = FakeClient(base, head, "mallory", [review("bob", "APPROVED", head)])
    assert not check_pull_request(root, client, 1).allowed


def test_author_cannot_approve_own_pr(pr):
    root, base, head = pr
    client = FakeClient(base, head, "anna", [review("anna", "APPROVED", head)])
    assert not check_pull_request(root, client, 1).allowed


def test_owner_authored_pr_needs_no_review(pr):
    root, base, head = pr
    assert check_pull_request(root, FakeClient(base, head, "olga", []), 1).allowed


def test_rules_change_in_pr_cannot_be_approved(pr):
    root, base, head = pr
    (root / ".tripwire" / "locks.json").write_text(json.dumps(dict(RULES, leaders=["mallory"])))
    git(root, "commit", "-qam", "seize")
    head = git(root, "rev-parse", "HEAD")
    client = FakeClient(base, head, "mallory", [review("lead", "APPROVED", head)])
    assert not check_pull_request(root, client, 1).allowed


def test_pagination_follows_link_header():
    pages = {
        "https://api.github.com/repos/o/r/pulls/1/reviews?per_page=100": (
            json.dumps([review("a", "APPROVED", "h")]).encode(),
            '<https://api.github.com/page2>; rel="next"',
        ),
        "https://api.github.com/page2": (json.dumps([review("b", "APPROVED", "h")]).encode(), ""),
    }
    client = GitHubClient("o/r", fetch=lambda url: pages[url])
    assert [r["user"]["login"] for r in client.get_reviews(1)] == ["a", "b"]
