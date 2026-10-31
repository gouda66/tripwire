from tripwire.config import RULES_PATH, parse_config
from tripwire.engine import change_digest, evaluate
from tripwire.blocks import normalize
from tripwire.models import Approval, FileChange

CONFIG = parse_config(
    """{
  "leaders": ["lead"],
  "locks": [
    {"id": "billing", "owners": ["olga"], "approvers": ["anna"]},
    {"id": "secrets", "owners": ["olga"], "paths": ["config/prod/", "*.pem"]}
  ]
}"""
)

OLD = "x = 1\n# @lock-begin billing\nrate = 5\n# @lock-end billing\ny = 2\n"
NEW = OLD.replace("rate = 5", "rate = 9")


def ch(old=OLD, new=NEW, path="app.py"):
    return [FileChange(path, old, new)]


def digest(old=OLD, new=NEW, lock="billing", path="app.py"):
    from tripwire.blocks import extract_blocks

    return change_digest(lock, path, extract_blocks(old).get(lock), extract_blocks(new).get(lock))


def test_owner_can_edit():
    assert evaluate(CONFIG, ch(), "olga").allowed


def test_leader_can_edit():
    assert evaluate(CONFIG, ch(), "lead").allowed


def test_stranger_blocked_and_told_whom_to_ask():
    d = evaluate(CONFIG, ch(), "mallory")
    assert not d.allowed
    msg = d.violations[0].message
    assert "olga" in msg and "anna" in msg and "lead" in msg


def test_approval_lets_stranger_through():
    ap = [Approval("billing", "anna", digest())]
    assert evaluate(CONFIG, ch(), "mallory", ap).allowed


def test_approval_void_after_further_edit():
    ap = [Approval("billing", "anna", digest())]
    newer = NEW.replace("rate = 9", "rate = 99")
    assert not evaluate(CONFIG, ch(new=newer), "mallory", ap).allowed


def test_cannot_approve_own_change():
    ap = [Approval("billing", "anna", digest())]
    # anna is an approver, not an owner: her own approval of her own change doesn't count
    assert not evaluate(CONFIG, ch(), "anna", ap).allowed


def test_approval_from_unauthorized_person_rejected():
    ap = [Approval("billing", "bob", digest())]
    assert not evaluate(CONFIG, ch(), "mallory", ap).allowed


def test_deleting_markers_is_blocked():
    stripped = "x = 1\nrate = 5\ny = 2\n"
    assert not evaluate(CONFIG, ch(new=stripped), "mallory").allowed


def test_removing_whole_block_is_blocked():
    assert not evaluate(CONFIG, ch(new="x = 1\ny = 2\n"), "mallory").allowed


def test_rules_file_leaders_only():
    c = [FileChange(RULES_PATH, "{}", '{"leaders": ["mallory"]}')]
    assert not evaluate(CONFIG, c, "olga").allowed
    assert evaluate(CONFIG, c, "lead").allowed


def test_whitespace_only_edit_passes():
    spaced = OLD.replace("rate = 5", "    rate = 5   \n\n")
    assert evaluate(CONFIG, ch(new=spaced), "mallory").allowed


def test_unprotected_code_passes():
    assert evaluate(CONFIG, ch(new=OLD.replace("y = 2", "y = 3")), "mallory").allowed


def test_path_lock_folder_and_glob():
    assert not evaluate(CONFIG, ch(None, "k=1", "config/prod/db.yml"), "mallory").allowed
    assert not evaluate(CONFIG, ch("a", "b", "keys/server.pem"), "mallory").allowed
    assert evaluate(CONFIG, ch("a", "b", "config/prod/db.yml"), "olga").allowed
    assert evaluate(CONFIG, ch("a", "b", "config/dev/db.yml"), "mallory").allowed


def test_unknown_block_id_is_leaders_only():
    new = OLD + "# @lock-begin mystery\nz = 1\n# @lock-end mystery\n"
    assert not evaluate(CONFIG, ch(new=new), "olga").allowed
    assert evaluate(CONFIG, ch(new=new), "lead").allowed


def test_unclosed_block_fails_closed():
    new = "# @lock-begin billing\nrate = 5\nextra = 1\n"
    old = "# @lock-begin billing\nrate = 5\n"
    assert not evaluate(CONFIG, ch(old, new), "mallory").allowed


def test_digest_depends_on_content():
    assert change_digest("a", "p", normalize("x"), normalize("y")) != change_digest("a", "p", normalize("x"), normalize("z"))
