"""GitHub adapter: approvals come from pull-request reviews.

A review only counts when it is the reviewer's latest review, its state is
APPROVED, and it was made on the PR's current head commit. Pushing new commits
therefore voids earlier approvals (the head sha changes).
"""

from __future__ import annotations

import os
from typing import Dict, Iterable, List, Optional, Set
from urllib.parse import quote

from .config import ConfigError
from .httpjson import Fetch, get_all, urlopen_fetch
from .models import Decision
from .review import check_review


class GitHubClient:
    def __init__(self, repo: str, token: Optional[str] = None, api_url: str = "https://api.github.com", fetch: Optional[Fetch] = None):
        self.repo, self.api_url = repo, api_url.rstrip("/")
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        self._fetch = fetch or urlopen_fetch(headers)

    @classmethod
    def from_env(cls, repo: Optional[str] = None) -> "GitHubClient":
        repo = repo or os.environ.get("GITHUB_REPOSITORY")
        if not repo:
            raise ConfigError("repository unknown; pass --github-repo or set GITHUB_REPOSITORY")
        return cls(repo, os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_API_URL", "https://api.github.com"))

    def _all(self, path: str) -> List[dict]:
        return get_all(self._fetch, "%s/repos/%s/%s?per_page=100" % (self.api_url, self.repo, path))

    def get_pull(self, number: int) -> dict:
        return self._all("pulls/%d" % number)[0]

    def get_reviews(self, number: int) -> List[dict]:
        return self._all("pulls/%d/reviews" % number)

    def get_branch_sha(self, branch: str) -> str:
        return self._all("branches/" + quote(branch, safe="/"))[0]["commit"]["sha"]

    def get_team_members(self, ref: str) -> List[str]:
        """Logins in a team given as "@org/team". Needs a token that may read org members."""
        org, slug = ref[1:].split("/", 1)
        url = "%s/orgs/%s/teams/%s/members?per_page=100" % (self.api_url, quote(org), quote(slug))
        try:
            return [m["login"] for m in get_all(self._fetch, url)]
        except Exception as exc:  # fail closed: an unresolved team must not silently shrink
            raise ConfigError("cannot read members of team %s (token needs read:org): %s" % (ref, exc))


def approved_logins(reviews: Iterable[dict], head_sha: str) -> Set[str]:
    """Logins whose latest decisive review is an approval of `head_sha`."""
    latest: Dict[str, dict] = {}
    for review in reviews:  # the API returns reviews oldest-first
        user = (review.get("user") or {}).get("login")
        if user and review.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            latest[user] = review
    return {u for u, r in latest.items() if r["state"] == "APPROVED" and r.get("commit_id") == head_sha}


def check_pull_request(root: str, client: GitHubClient, number: int) -> Decision:
    pr = client.get_pull(number)
    head_sha = pr["head"]["sha"]
    approvers = approved_logins(client.get_reviews(number), head_sha)
    # pr["base"]["sha"] is stale once the target branch moves; use its current tip for the rules.
    target_sha = client.get_branch_sha(pr["base"]["ref"])
    return check_review(root, target_sha, head_sha, pr["user"]["login"], approvers, client.get_team_members)
