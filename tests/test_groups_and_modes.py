import json
import os
import subprocess

import pytest

from tripwire.config import ConfigError, parse_config
from tripwire.engine import change_digest, evaluate
from tripwire.github import check_pull_request
from tripwire.models import FileChange


def cfg(**extra):
    base = {
        "groups": {"billing": ["bob", "carol"], "all": ["@billing", "dave"], "sec": ["@org/security"]},
        "leaders": ["lead"],
        "locks": [{"id": "billing", "owners": ["@billing"], "approvers": ["@all"]}],
    }
    base.update(extra)
    return parse_config(json.dumps(base))


CODE = "def f():\n    a = 1\n    return a\n"
BLOCK = "# @lock-begin billing\n%s# @lock-end billing\n"


def change(old, new, path="app.py"):
    return [FileChange(path, old, new)]


# ---- groups -----------------------------------------------------------------

def test_group_members_are_expanded_including_nested_groups():
    c = cfg()
    lock = c.get("billing")
    assert lock.owners == ("bob", "carol")
    assert set(lock.approvers) == {"bob", "carol", "dave"}


def test_group_member_can_edit_and_non_member_cannot():
    old, new = BLOCK % "rate = 5\n", BLOCK % "rate = 9\n"
    assert evaluate(cfg(), change(old, new), "carol").allowed
    assert not evaluate(cfg(), change(old, new), "mallory").allowed


def test_unknown_group_and_cycles_are_errors():
    with pytest.raises(ConfigError):
        cfg(locks=[{"id": "x", "owners": ["@nope"]}])
    with pytest.raises(ConfigError):
        cfg(groups={"a": ["@b"], "b": ["@a"]}, locks=[{"id": "x", "owners": ["@a"]}])


def test_platform_team_ref_survives_parsing_and_expands_on_demand():
    c = cfg(locks=[{"id": "billing", "owners": ["bob"], "approvers": ["@org/security", "@sec"]}])
    assert c.team_refs() == {"@org/security"}
    expanded = c.expand_teams(lambda ref: ["sam", "bob"])
    assert expanded.get("billing").approvers == ("sam", "bob")


def test_unresolved_team_never_matches_a_person():
    c = cfg(locks=[{"id": "billing", "owners": ["@org/security"]}])
    old, new = BLOCK % "rate = 5\n", BLOCK % "rate = 9\n"
    assert not evaluate(c, change(old, new), "sam").allowed


# ---- whitespace modes -------------------------------------------------------

def test_default_ignores_reindenting():
    old = BLOCK % "    a = 1\n"
    new = BLOCK % "a = 1\n"
    assert evaluate(cfg(), change(old, new), "mallory").allowed


def test_indent_mode_catches_reindenting_in_python_blocks():
    c = cfg(whitespace="indent")
    old = BLOCK % "if x:\n    y = 1\n"
    new = BLOCK % "if x:\ny = 1\n"
    assert not evaluate(c, change(old, new), "mallory").allowed
    assert evaluate(c, change(old, new), "carol").allowed  # owner still free


def test_indent_mode_still_ignores_trailing_space_and_blank_lines():
    c = cfg(whitespace="indent")
    old = BLOCK % "    y = 1\n"
    new = BLOCK % "    y = 1   \n\n\n"
    assert evaluate(c, change(old, new), "mallory").allowed


def test_per_lock_override():
    c = cfg(locks=[{"id": "billing", "owners": ["bob"], "whitespace": "indent"}, {"id": "other", "owners": ["bob"]}])
    old_b, new_b = BLOCK % "    y = 1\n", BLOCK % "y = 1\n"
    assert not evaluate(c, change(old_b, new_b), "mallory").allowed
    old_o = "# @lock-begin other\n    y = 1\n# @lock-end other\n"
    new_o = "# @lock-begin other\ny = 1\n# @lock-end other\n"
    assert evaluate(c, change(old_o, new_o), "mallory").allowed


def test_path_lock_respects_mode():
    c = parse_config(json.dumps({"whitespace": "indent", "locks": [{"id": "py", "owners": ["bob"], "paths": ["src/"]}]}))
    assert not evaluate(c, change("if x:\n    y\n", "if x:\ny\n", "src/a.py"), "mallory").allowed


def test_bad_whitespace_value_is_an_error():
    with pytest.raises(ConfigError):
        cfg(whitespace="tabs")


def test_digest_differs_between_modes_for_indent_changes():
    a = change_digest("x", "p", ("    y",), ("y",))
    assert a != change_digest("x", "p", ("y",), ("y",))


# ---- GitHub teams -----------------------------------------------------------

def git(cwd, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    return subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True).stdout.strip()


class FakeGitHub:
    def __init__(self, base, head, author, reviewers, teams):
        self.pr = {"base": {"sha": "stale", "ref": "main"}, "head": {"sha": head}, "user": {"login": author}}
        self.reviews = [{"user": {"login": r}, "state": "APPROVED", "commit_id": head} for r in reviewers]
        self.tip, self.teams = base, teams

    def get_pull(self, n):
        return self.pr

    def get_reviews(self, n):
        return self.reviews

    def get_branch_sha(self, b):
        return self.tip

    def get_team_members(self, ref):
        return self.teams[ref]


@pytest.fixture
def pr(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / ".tripwire").mkdir()
    rules = {"leaders": ["lead"], "locks": [{"id": "billing", "owners": ["olga"], "approvers": ["@org/finance"]}]}
    (tmp_path / ".tripwire" / "locks.json").write_text(json.dumps(rules))
    (tmp_path / "app.py").write_text(BLOCK % "rate = 5\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "init")
    base = git(tmp_path, "rev-parse", "HEAD")
    git(tmp_path, "checkout", "-q", "-b", "feature")
    (tmp_path / "app.py").write_text(BLOCK % "rate = 9\n")
    git(tmp_path, "commit", "-qam", "bump")
    return tmp_path, base, git(tmp_path, "rev-parse", "HEAD")


def test_github_team_member_approval_unlocks_the_pr(pr):
    root, base, head = pr
    teams = {"@org/finance": ["Fiona", "Fred"]}
    assert check_pull_request(root, FakeGitHub(base, head, "mallory", ["fiona"], teams), 1).allowed
    assert not check_pull_request(root, FakeGitHub(base, head, "mallory", ["zed"], teams), 1).allowed
    assert not check_pull_request(root, FakeGitHub(base, head, "fiona", ["fiona"], teams), 1).allowed  # own PR


def test_github_team_lookup_failure_fails_closed(pr):
    root, base, head = pr

    class Broken(FakeGitHub):
        def get_team_members(self, ref):
            raise ConfigError("cannot read members of team %s" % ref)

    with pytest.raises(ConfigError):
        check_pull_request(root, Broken(base, head, "mallory", ["fiona"], {}), 1)
