import json
import os
import subprocess

import pytest

from tripwire.gitea import GiteaClient, approved_logins, check_pull_request

RULES = {
    "leaders": ["lead"],
    "locks": [{"id": "billing", "owners": ["olga"], "approvers": ["Anna"]}],
}
CODE = "x = 1\n# @lock-begin billing\nrate = 5\n# @lock-end billing\n"


def git(cwd, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    return subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True).stdout.strip()


def review(user, state, sha, **extra):
    return {"user": {"login": user}, "state": state, "commit_id": sha, **extra}


class FakeClient:
    def __init__(self, base, head, author, reviews):
        self.pr = {"base": {"sha": "stale-sha", "ref": "main"}, "head": {"sha": head}, "user": {"login": author}}
        self.reviews, self.tip = reviews, base

    def get_pull(self, number):
        return self.pr

    def get_reviews(self, number):
        return self.reviews

    def get_branch_sha(self, branch):
        return self.tip


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
    return tmp_path, base, git(tmp_path, "rev-parse", "HEAD")


def test_review_states_filtered():
    reviews = [
        review("a", "APPROVED", "h"),
        review("b", "APPROVED", "h", stale=True),
        review("c", "APPROVED", "h", dismissed=True),
        review("d", "APPROVED", "old"),
        review("e", "APPROVED", "h"),
        review("e", "REQUEST_CHANGES", "h"),
        review("f", "APPROVED", "h"),
        review("f", "COMMENT", "h"),
    ]
    assert approved_logins(reviews, "h") == {"a", "f"}


def test_pr_flow(pr):
    root, base, head = pr
    assert not check_pull_request(root, FakeClient(base, head, "mallory", []), 1).allowed
    assert check_pull_request(root, FakeClient(base, head, "mallory", [review("anna", "APPROVED", head)]), 1).allowed
    assert not check_pull_request(root, FakeClient(base, head, "mallory", [review("anna", "APPROVED", head, stale=True)]), 1).allowed
    assert not check_pull_request(root, FakeClient(base, head, "anna", [review("anna", "APPROVED", head)]), 1).allowed
    assert check_pull_request(root, FakeClient(base, head, "olga", []), 1).allowed


def test_client_urls():
    seen = []

    def fetch(url):
        seen.append(url)
        return b'{"commit": {"id": "abc"}}', ""

    client = GiteaClient("o/r", "https://git.example/api/v1/", "t", fetch=fetch)
    assert client.get_branch_sha("release/1") == "abc"
    assert seen == ["https://git.example/api/v1/repos/o/r/branches/release/1"]


def test_from_env_derives_api_url(monkeypatch):
    for var in ("GITEA_API_URL", "GITHUB_API_URL", "GITEA_REPOSITORY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://git.example/")
    assert GiteaClient.from_env().api_url == "https://git.example/api/v1"
