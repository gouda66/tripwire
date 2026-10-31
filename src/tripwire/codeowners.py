"""Import a CODEOWNERS file as path locks.

CODEOWNERS uses "last matching pattern wins"; tripwire locks are additive, so
every matching pattern's owners may edit. That is stricter than GitHub only when
a later pattern deliberately narrows an earlier one.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

CANDIDATES = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS", ".gitlab/CODEOWNERS")
GLOB = re.compile(r"[*?\[]")


def convert_pattern(pattern: str) -> List[str]:
    """Translate one gitignore-style pattern into tripwire path patterns."""
    p = pattern.strip()
    anchored = p.startswith("/")
    p = p.lstrip("/")
    if p.endswith("/**"):
        p = p[:-2]  # "docs/**" -> "docs/"
    if p.startswith("**/"):
        base = convert_pattern("/" + p[3:])  # anchored form, then also under any directory
        return list(dict.fromkeys(base + ["*/" + b for b in base]))
    is_dir = p.endswith("/")
    body = p.rstrip("/")
    if not body:
        return ["*"]  # "/" owns the whole repository
    if "/" in body:
        anchored = True  # a slash inside the pattern anchors it, as in .gitignore
    out: List[str] = []
    if is_dir:
        out.append(body + "/")
        if not anchored:
            out += ["*/" + body + "/", "*/" + body + "/*"]
    else:
        out.append(body)
        if not GLOB.search(body):
            out.append(body + "/")  # may be a directory
        if not anchored:
            out.append("*/" + body)
            if not GLOB.search(body):
                out.append("*/" + body + "/*")
    return list(dict.fromkeys(out))


def parse(text: str) -> Tuple[List[Tuple[str, List[str]]], List[str]]:
    """Return ([(pattern, owners)], warnings). Later duplicates replace earlier ones."""
    entries: Dict[str, List[str]] = {}
    warnings: List[str] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #")[0].strip() if " #" in raw else raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") or line.startswith("^["):
            warnings.append("line %d: sections are not supported; section default owners are ignored" % n)
            continue
        tokens = line.split()
        pattern, owners = tokens[0], []
        for tok in tokens[1:]:
            if tok.startswith("@"):
                owners.append(tok if "/" in tok else tok[1:])
            else:
                warnings.append("line %d: owner %r is not a GitHub / GitLab user or team and was skipped" % (n, tok))
        if not owners:
            entries.pop(pattern, None)  # an owner-less line un-owns the pattern
            continue
        entries.pop(pattern, None)
        entries[pattern] = owners
    return list(entries.items()), warnings


def to_config(entries: List[Tuple[str, List[str]]], leaders: List[str]) -> dict:
    locks = []
    for i, (pattern, owners) in enumerate(entries, 1):
        locks.append({"id": "codeowners-%d" % i, "owners": owners, "paths": convert_pattern(pattern)})
    return {"leaders": leaders, "locks": locks}
