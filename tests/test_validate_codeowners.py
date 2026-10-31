import json
import os
import subprocess

import pytest

from tripwire import codeowners
from tripwire.cli import main
from tripwire.config import Lock, parse_config
from tripwire.engine import evaluate
from tripwire.models import FileChange
from tripwire.validate import validate


def git(cwd, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    return subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True).stdout.strip()


def matches(pattern, path):
    return Lock("x", paths=tuple(codeowners.convert_pattern(pattern))).matches_path(path)


# ---- CODEOWNERS pattern translation ------------------------------------------

@pytest.mark.parametrize(
    "pattern,path,expected",
    [
        ("/docs/", "docs/a.md", True),
        ("/docs/", "x/docs/a.md", False),
        ("docs/", "docs/a.md", True),
        ("docs/", "x/y/docs/a.md", True),
        ("*.js", "a.js", True),
        ("*.js", "src/deep/a.js", True),
        ("*.js", "a.py", False),
        ("/src/*.py", "src/a.py", True),
        ("/src/*.py", "other/a.py", False),
        ("Makefile", "Makefile", True),
        ("Makefile", "sub/Makefile", True),
        ("Makefile", "Makefile2", False),
        ("docs/**", "docs/a/b.md", True),
        ("docs/**", "other/a.md", False),
        ("**/test/*.py", "test/a.py", True),
        ("**/test/*.py", "x/test/a.py", True),
        ("/src", "src/a.py", True),
        ("/src", "src", True),
        ("/", "anything/at/all.txt", True),
        ("*", "a/b/c", True),
    ],
)
def test_pattern_translation(pattern, path, expected):
    assert matches(pattern, path) is expected


def test_parse_owners_and_warnings():
    text = """
# comment
*.js @alice @org/frontend   # trailing comment
docs/ bob@example.com @carol
/src/ @dave
[Section] @x
/old/ @erin
/old/
*.js @alice2
"""
    entries, warnings = codeowners.parse(text)
    got = dict(entries)
    assert got["*.js"] == ["alice2"]  # later duplicate replaces the earlier one
    assert got["docs/"] == ["carol"]
    assert got["/src/"] == ["dave"]
    assert "/old/" not in got  # an owner-less line un-owns the pattern
    assert any("bob@example.com" in w for w in warnings)
    assert any("sections" in w for w in warnings)
    entries2, _ = codeowners.parse("*.py @a/b @c\n")
    assert dict(entries2)["*.py"] == ["@a/b", "c"]


def test_imported_config_enforces_owners():
    entries, _ = codeowners.parse("/payments/ @pay-team-lead @olga\n*.sql @dba\n")
    config = parse_config(json.dumps(codeowners.to_config(entries, ["lead"])))
    change = lambda path: [FileChange(path, "a", "b")]
    assert not evaluate(config, change("payments/x.py"), "mallory").allowed
    assert evaluate(config, change("payments/x.py"), "olga").allowed
    assert evaluate(config, change("db/schema.sql"), "dba").allowed
    assert not evaluate(config, change("db/schema.sql"), "olga").allowed
    assert evaluate(config, change("README.md"), "mallory").allowed
    assert evaluate(config, change("README.md"), "mallory").allowed and evaluate(config, change("payments/x.py"), "lead").allowed


# ---- CLI --------------------------------------------------------------------

@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "CODEOWNERS").write_text("/src/ @olga\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = 1\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "init")
    return tmp_path


def test_import_codeowners_cli_prints_and_writes(repo, capsys):
    assert main(["--repo", str(repo), "import-codeowners", "--leader", "lead"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["leaders"] == ["lead"] and printed["locks"][0]["owners"] == ["olga"]
    assert main(["--repo", str(repo), "import-codeowners", "--write"]) == 0
    assert (repo / ".tripwire" / "locks.json").exists()
    assert main(["--repo", str(repo), "import-codeowners", "--write"]) == 1  # refuses to overwrite
    assert main(["--repo", str(repo), "import-codeowners", "--write", "--force"]) == 0


def test_import_codeowners_without_file_is_an_error(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    assert main(["--repo", str(tmp_path), "import-codeowners"]) == 2


# ---- validate ---------------------------------------------------------------

@pytest.fixture
def project(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "app.py").write_text("# @lock-begin billing\nx = 1\n# @lock-end billing\n# @lock-begin ghost\ny = 2\n# @lock-end ghost\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("z = 1\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "init")
    return tmp_path


def run_validate(project, rules):
    return validate(str(project), json.dumps(rules))


def test_validate_clean_config_has_no_findings(project):
    rules = {"leaders": ["lead"], "locks": [
        {"id": "billing", "owners": ["o"]}, {"id": "ghost", "owners": ["o"]}, {"id": "src", "owners": ["o"], "paths": ["src/"]}]}
    assert run_validate(project, rules) == ([], [])


def test_validate_reports_errors_for_bad_config(project):
    errors, _ = run_validate(project, {"locks": [{"id": "a"}, {"id": "a"}]})
    assert errors and "duplicate" in errors[0]
    assert validate(str(project), "{not json")[0]


def test_validate_warnings(project):
    rules = {"locks": [
        {"id": "billing"},                                  # no owners
        {"id": "unused", "owners": ["o"]},                  # no paths, no markers
        {"id": "nopath", "owners": ["o"], "paths": ["nothing/"]},
        {"id": "team", "owners": ["@org/t"], "paths": ["src/"]}]}
    errors, warnings = run_validate(project, rules)
    text = "\n".join(warnings)
    assert errors == []
    assert "no leaders" in text
    assert "block 'ghost' has markers but no lock" in text
    assert "lock 'billing' has no owners or approvers" in text
    assert "lock 'unused' has no paths and no @lock-begin" in text
    assert "lock 'nopath': none of its paths match" in text
    assert "@org/t" in text


def test_validate_flags_unclosed_and_stray_markers(project):
    (project / "bad.py").write_text("# @lock-end orphan\n# @lock-begin open\nv = 1\n")
    git(project, "add", "-A")
    _, warnings = run_validate(project, {"leaders": ["l"], "locks": []})
    text = "\n".join(warnings)
    assert "without a matching @lock-begin" in text and "never closed" in text


def test_validate_cli_exit_codes(project, capsys):
    (project / ".tripwire").mkdir()
    rules = project / ".tripwire" / "locks.json"
    rules.write_text(json.dumps({"leaders": ["l"], "locks": []}))
    assert main(["--repo", str(project), "validate"]) == 0
    rules.write_text("{broken")
    assert main(["--repo", str(project), "validate"]) == 1
    rules.unlink()
    assert main(["--repo", str(project), "validate"]) == 2
