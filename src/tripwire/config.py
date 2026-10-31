from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from typing import Optional, Tuple

RULES_PATH = ".tripwire/locks.json"
APPROVALS_PATH = ".tripwire/approvals.json"


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Lock:
    id: str
    owners: Tuple[str, ...] = ()
    approvers: Tuple[str, ...] = ()
    paths: Tuple[str, ...] = ()

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

    def get(self, lock_id: str) -> Optional[Lock]:
        for lock in self.locks:
            if lock.id == lock_id:
                return lock
        return None

    def everyone(self) -> set:
        people = set(self.leaders)
        for lock in self.locks:
            people.update(lock.owners)
            people.update(lock.approvers)
        return people


def _names(obj, key: str) -> Tuple[str, ...]:
    value = obj.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError("'%s' must be a list of strings" % key)
    return tuple(value)


def parse_config(text: str) -> Config:
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise ConfigError("invalid JSON in %s: %s" % (RULES_PATH, exc))
    if not isinstance(raw, dict):
        raise ConfigError("%s must be a JSON object" % RULES_PATH)
    locks = []
    seen = set()
    for item in raw.get("locks", []):
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ConfigError("every lock needs a string 'id'")
        if item["id"] in seen:
            raise ConfigError("duplicate lock id '%s'" % item["id"])
        seen.add(item["id"])
        locks.append(
            Lock(
                id=item["id"],
                owners=_names(item, "owners"),
                approvers=_names(item, "approvers"),
                paths=_names(item, "paths"),
            )
        )
    return Config(leaders=_names(raw, "leaders"), locks=tuple(locks))
