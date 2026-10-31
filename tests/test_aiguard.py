import io
import json
import os
import subprocess
import sys

import pytest

from tripwire.cli import main

RULES = {
    "leaders": ["lead"],
    "locks": [{"id": "billing", "owners": ["olga"], "approvers": ["anna"]}],
}
CODE = "x = 1\n# @lock-begin billing\nrate = 5\n# @lock-end billing\ny = 2\n"


def git(cwd, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    return subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / ".tripwire").mkdir()
    (tmp_path / ".tripwire" / "locks.json").write_text(json.dumps(RULES))
    (tmp_path / "app.py").write_text(CODE)
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "init")
    monkeypatch.delenv("TRIPWIRE_AI_ACTOR", raising=False)
    return tmp_path


class FakeTTY(io.StringIO):
    def isatty(self):
        return True


def tty(monkeypatch, text):
    monkeypatch.setattr(sys, "stdin", FakeTTY(text))


def hook(repo, monkeypatch, tool, tool_input):
    payload = {"tool_name": tool, "tool_input": tool_input, "cwd": str(repo)}
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    return main(["--repo", str(repo), "claude-hook"])


def edit(repo, old, new, **kw):
    return {"file_path": str(repo / "app.py"), "old_string": old, "new_string": new, **kw}


def test_edit_of_protected_block_is_blocked_before_it_happens(repo, monkeypatch, capsys):
    assert hook(repo, monkeypatch, "Edit", edit(repo, "rate = 5", "rate = 9")) == 2
    err = capsys.readouterr().err
    assert "billing" in err and "tripwire grant" in err
    assert (repo / "app.py").read_text() == CODE  # hook never touches the file


def test_edit_of_unprotected_code_is_allowed(repo, monkeypatch):
    assert hook(repo, monkeypatch, "Edit", edit(repo, "y = 2", "y = 3")) == 0


def test_write_that_changes_protected_block_is_blocked(repo, monkeypatch):
    new = CODE.replace("rate = 5", "rate = 9")
    assert hook(repo, monkeypatch, "Write", {"file_path": str(repo / "app.py"), "content": new}) == 2


def test_write_that_leaves_block_unchanged_is_allowed(repo, monkeypatch):
    new = CODE.replace("y = 2", "y = 7")
    assert hook(repo, monkeypatch, "Write", {"file_path": str(repo / "app.py"), "content": new}) == 0


def test_multiedit_is_evaluated_as_a_whole(repo, monkeypatch):
    edits = [{"old_string": "y = 2", "new_string": "y = 3"}, {"old_string": "rate = 5", "new_string": "rate = 6"}]
    assert hook(repo, monkeypatch, "MultiEdit", {"file_path": str(repo / "app.py"), "edits": edits}) == 2


def test_deleting_markers_is_blocked(repo, monkeypatch):
    assert hook(repo, monkeypatch, "Edit", edit(repo, "# @lock-begin billing\n", "")) == 2


def test_failing_edit_is_left_to_the_tool(repo, monkeypatch):
    assert hook(repo, monkeypatch, "Edit", edit(repo, "no such text", "z")) == 0


def test_ai_actor_can_be_made_owner(repo, monkeypatch):
    monkeypatch.setenv("TRIPWIRE_AI_ACTOR", "olga")
    assert hook(repo, monkeypatch, "Edit", edit(repo, "rate = 5", "rate = 9")) == 0


def test_path_outside_repo_and_other_tools_are_ignored(repo, monkeypatch, tmp_path_factory):
    other = tmp_path_factory.mktemp("elsewhere") / "f.py"
    assert hook(repo, monkeypatch, "Write", {"file_path": str(other), "content": "x"}) == 0
    assert hook(repo, monkeypatch, "Read", {"file_path": str(repo / "app.py")}) == 0


def test_bash_cannot_touch_approvals_or_grant(repo, monkeypatch):
    assert hook(repo, monkeypatch, "Bash", {"command": "tripwire grant abc --approver anna"}) == 2
    assert hook(repo, monkeypatch, "Bash", {"command": "echo [] > .tripwire/approvals.json"}) == 2
    assert hook(repo, monkeypatch, "Bash", {"command": "ls"}) == 0


def test_agent_cannot_edit_approvals_or_rules_files(repo, monkeypatch):
    f = {"file_path": str(repo / ".tripwire" / "approvals.json"), "content": "[]"}
    assert hook(repo, monkeypatch, "Write", f) == 2
    r = {"file_path": str(repo / ".tripwire" / "locks.json"), "content": json.dumps(dict(RULES, leaders=["ai-agent"]))}
    assert hook(repo, monkeypatch, "Write", r) == 2


def test_grant_then_same_edit_is_allowed_but_other_edit_is_not(repo, monkeypatch, capsys):
    e = edit(repo, "rate = 5", "rate = 9")
    assert hook(repo, monkeypatch, "Edit", e) == 2
    assert main(["--repo", str(repo), "pending"]) == 0
    digest = json.loads((repo / ".git" / "tripwire" / "pending.json").read_text())[0]["digest"]
    tty(monkeypatch, "bob\n")
    assert main(["--repo", str(repo), "grant", digest[:10], "--approver", "bob"]) == 1  # not an approver
    tty(monkeypatch, "olga\n")
    assert main(["--repo", str(repo), "grant", digest[:10], "--approver", "anna"]) == 1  # wrong confirmation
    assert not (repo / ".tripwire" / "approvals.json").exists()
    tty(monkeypatch, "anna\n")
    assert main(["--repo", str(repo), "grant", digest[:10], "--approver", "anna"]) == 0
    assert hook(repo, monkeypatch, "Edit", e) == 0
    assert hook(repo, monkeypatch, "Edit", edit(repo, "rate = 5", "rate = 10")) == 2  # approval was for rate = 9


def test_grant_refuses_non_interactive_use(repo, monkeypatch):
    hook(repo, monkeypatch, "Edit", edit(repo, "rate = 5", "rate = 9"))
    digest = json.loads((repo / ".git" / "tripwire" / "pending.json").read_text())[0]["digest"]
    monkeypatch.setattr(sys, "stdin", io.StringIO("anna\n"))  # piped input is not a terminal
    assert main(["--repo", str(repo), "grant", digest[:10], "--approver", "anna"]) == 1
    assert not (repo / ".tripwire" / "approvals.json").exists()


def test_install_claude_hook_is_idempotent_and_keeps_other_settings(repo):
    (repo / ".claude").mkdir()
    (repo / ".claude" / "settings.json").write_text(json.dumps({"model": "x"}))
    assert main(["--repo", str(repo), "install-claude-hook"]) == 0
    assert main(["--repo", str(repo), "install-claude-hook"]) == 0
    settings = json.loads((repo / ".claude" / "settings.json").read_text())
    assert settings["model"] == "x"
    assert len(settings["hooks"]["PreToolUse"]) == 1


def test_not_a_git_repo_is_allowed(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"tool_name": "Write", "tool_input": {}})))
    assert main(["--repo", str(tmp_path), "claude-hook"]) == 0
