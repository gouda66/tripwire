from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, replace
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

RULES_PATH = ".tripwire/locks.json"
APPROVALS_PATH = ".tripwire/approvals.json"
WHITESPACE_MODES = ("ignore", "indent")
TEAM_REF = re.compile(r"^@[^/@\s]+/[^/@\s]+$")  # @org/team, resolved by a platform adapter
GROUP_REF = re.compile(r"^@[^/@\s]+$")  # @name, defined under "groups" in the rules file


class ConfigError(Exception):
    pass


def is_team_ref(name: str) -> bool:
    return bool(TEAM_REF.match(name))


@dataclass(frozen=True)
class Lock:
    id: str
    owners: Tuple[str, ...] = ()
    approvers: Tuple[str, ...] = ()
    paths: Tuple[str, ...] = ()
    whitespace: str = ""  # "" inherits the global setting

    def matches_path(self, path: str) -> bool:
        for pat in self.paths:
            if pat.endswith("/"):
                if path.startswith(pat):
                    return True
            elif fnmatch.fnmatchcase(path, pat):
                return True
        return False


@dataclass(frozen=True)
class Config:
    leaders: Tuple[str, ...]
    locks: Tuple[Lock, ...]
    whitespace: str = "ignore"

    def get(self, lock_id: str) -> Optional[Lock]:
        for lock in self.locks:
            if lock.id == lock_id:
                return lock
        return None

    def mode_for(self, lock_id: str) -> str:
        lock = self.get(lock_id)
        return (lock.whitespace if lock and lock.whitespace else self.whitespace)

    def everyone(self) -> set:
        people = set(self.leaders)
        for lock in self.locks:
            people.update(lock.owners)
            people.update(lock.approvers)
        return people

    def team_refs(self) -> Set[str]:
        return {n for n in self.everyone() if is_team_ref(n)}

    def expand_teams(self, resolver: Callable[[str], Sequence[str]]) -> "Config":
        """Replace @org/team entries by the team's members (platform adapters supply `resolver`)."""
        cache: Dict[str, Tuple[str, ...]] = {}

        def expand(names: Tuple[str, ...]) -> Tuple[str, ...]:
            out: List[str] = []
            for n in names:
                if is_team_ref(n):
                    if n not in cache:
                        cache[n] = tuple(resolver(n))
                    out.extend(cache[n])
                else:
                    out.append(n)
            return tuple(dict.fromkeys(out))

        return Config(
            leaders=expand(self.leaders),
            locks=tuple(replace(l, owners=expand(l.owners), approvers=expand(l.approvers)) for l in self.locks),
            whitespace=self.whitespace,
        )


def _names(obj, key: str) -> Tuple[str, ...]:
    value = obj.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError("'%s' must be a list of strings" % key)
    return tuple(value)


def _mode(value, where: str) -> str:
    if value not in WHITESPACE_MODES:
        raise ConfigError("%s: whitespace must be one of %s" % (where, ", ".join(WHITESPACE_MODES)))
    return value


def _expand_groups(groups: Dict[str, Tuple[str, ...]], names: Tuple[str, ...], trail: Tuple[str, ...] = ()) -> Tuple[str, ...]:
    out: List[str] = []
    for n in names:
        if is_team_ref(n) or not GROUP_REF.match(n):
            out.append(n)
            continue
        group = n[1:]
        if group not in groups:
            raise ConfigError("unknown group '%s'" % n)
        if group in trail:
            raise ConfigError("groups refer to each other in a cycle: %s" % " -> ".join(trail + (group,)))
        out.extend(_expand_groups(groups, groups[group], trail + (group,)))
    return tuple(dict.fromkeys(out))


def parse_config(text: str) -> Config:
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise ConfigError("invalid JSON in %s: %s" % (RULES_PATH, exc))
    if not isinstance(raw, dict):
        raise ConfigError("%s must be a JSON object" % RULES_PATH)

    raw_groups = raw.get("groups", {})
    if not isinstance(raw_groups, dict):
        raise ConfigError("'groups' must be an object of name -> list of names")
    groups = {name: _names(raw_groups, name) for name in raw_groups}

    locks = []
    seen = set()
    for item in raw.get("locks", []):
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ConfigError("every lock needs a string 'id'")
        if item["id"] in seen:
            raise ConfigError("duplicate lock id '%s'" % item["id"])
        seen.add(item["id"])
        mode = _mode(item["whitespace"], "lock '%s'" % item["id"]) if "whitespace" in item else ""
        locks.append(
            Lock(
                id=item["id"],
                owners=_expand_groups(groups, _names(item, "owners")),
                approvers=_expand_groups(groups, _names(item, "approvers")),
                paths=_names(item, "paths"),
                whitespace=mode,
            )
        )
    return Config(
        leaders=_expand_groups(groups, _names(raw, "leaders")),
        locks=tuple(locks),
        whitespace=_mode(raw.get("whitespace", "ignore"), "top level"),
    )
