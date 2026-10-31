"""Gitea / Forgejo adapter: approvals come from pull-request reviews.

A review counts when it is the reviewer's latest decisive review, its state is
APPROVED, it is neither stale nor dismissed, and it was made on the PR's
current head commit.
"""

from __future__ import annotations

import os
from typing import Dict, Iterable, List, Optional, Set
from urllib.parse import quote

from .config import ConfigError
from .httpjson import Fetch, get_all, urlopen_fetch
from .models import Decision
from .review import check_review


class GiteaClient:
    def __init__(self, repo: str, api_url: str, token: Optional[str] = None, fetch: Optional[Fetch] = None):
        self.repo, self.api_url = repo, api_url.rstrip("/")
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = "token " + token
        self._fetch = fetch or urlopen_fetch(headers)

    @classmethod
    def from_env(cls, repo: Optional[str] = None, api_url: Optional[str] = None) -> "GiteaClient":
        repo = repo or os.environ.get("GITEA_REPOSITORY") or os.environ.get("GITHUB_REPOSITORY")
        if not repo:
            raise ConfigError("repository unknown; pass --gitea-repo or set GITHUB_REPOSITORY")
        api_url = api_url or os.environ.get("GITEA_API_URL") or os.environ.get("GITHUB_API_URL")
        if not api_url and os.environ.get("GITHUB_SERVER_URL"):
            api_url = os.environ["GITHUB_SERVER_URL"].rstrip("/") + "/api/v1"
        if not api_url:
            raise ConfigError("server unknown; pass --gitea-url (e.g. https://git.example.com/api/v1)")
        return cls(repo, api_url, os.environ.get("GITEA_TOKEN") or os.environ.get("GITHUB_TOKEN"))

    def _all(self, path: str, query: str = "") -> List[dict]:
        return get_all(self._fetch, "%s/repos/%s/%s%s" % (self.api_url, self.repo, path, query))

    def get_pull(self, number: int) -> dict:
        return self._all("pulls/%d" % number)[0]

    def get_reviews(self, number: int) -> List[dict]:
        return self._all("pulls/%d/reviews" % number, "?limit=50")

    def get_branch_sha(self, branch: str) -> str:
        return self._all("branches/" + quote(branch, safe="/"))[0]["commit"]["id"]


def approved_logins(reviews: Iterable[dict], head_sha: str) -> Set[str]:
    latest: Dict[str, dict] = {}
    for review in reviews:  # oldest first
        user = (review.get("user") or {}).get("login")
        if user and review.get("state") in ("APPROVED", "REQUEST_CHANGES"):
            latest[user] = review
    return {
        u
        for u, r in latest.items()
        if r["state"] == "APPROVED" and not r.get("stale") and not r.get("dismissed") and r.get("commit_id") == head_sha
    }


def check_pull_request(root: str, client: GiteaClient, number: int) -> Decision:
    pr = client.get_pull(number)
    head_sha = pr["head"]["sha"]
    approvers = approved_logins(client.get_reviews(number), head_sha)
    target_sha = client.get_branch_sha(pr["base"]["ref"])
    return check_review(root, target_sha, head_sha, pr["user"]["login"], approvers)
