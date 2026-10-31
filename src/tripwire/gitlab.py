"""GitLab adapter: approvals come from merge-request approvals.

The approvals endpoint is not tied to a commit, so stale approvals are only
voided if the project setting "Remove all approvals when commits are added to
the source branch" is enabled. Turn it on; tripwire cannot verify it.
"""

from __future__ import annotations

import os
from typing import Iterable, List, Optional, Set
from urllib.parse import quote

from .config import ConfigError
from .httpjson import Fetch, get_all, urlopen_fetch
from .models import Decision
from .review import check_review


class GitLabClient:
    def __init__(self, project: str, token: Optional[str] = None, api_url: str = "https://gitlab.com/api/v4",
                 job_token: bool = False, fetch: Optional[Fetch] = None):
        self.project, self.api_url = quote(str(project), safe=""), api_url.rstrip("/")
        headers = {}
        if token:
            headers["JOB-TOKEN" if job_token else "PRIVATE-TOKEN"] = token
        self._fetch = fetch or urlopen_fetch(headers)

    @classmethod
    def from_env(cls, project: Optional[str] = None) -> "GitLabClient":
        project = project or os.environ.get("CI_PROJECT_ID")
        if not project:
            raise ConfigError("project unknown; pass --gitlab-project or set CI_PROJECT_ID")
        api_url = os.environ.get("CI_API_V4_URL", "https://gitlab.com/api/v4")
        token = os.environ.get("GITLAB_TOKEN")
        if token:
            return cls(project, token, api_url)
        return cls(project, os.environ.get("CI_JOB_TOKEN"), api_url, job_token=True)

    def _all(self, path: str) -> List[dict]:
        return get_all(self._fetch, "%s/projects/%s/merge_requests/%s" % (self.api_url, self.project, path))

    def get_merge_request(self, iid: int) -> dict:
        return self._all("%d" % iid)[0]

    def get_approvals(self, iid: int) -> dict:
        return self._all("%d/approvals" % iid)[0]

    def get_branch_sha(self, branch: str) -> str:
        url = "%s/projects/%s/repository/branches/%s" % (self.api_url, self.project, quote(branch, safe=""))
        return get_all(self._fetch, url)[0]["commit"]["id"]


def approved_usernames(approvals: dict) -> Set[str]:
    return {(a.get("user") or {}).get("username") for a in approvals.get("approved_by", [])} - {None}


def check_merge_request(root: str, client: GitLabClient, iid: int) -> Decision:
    mr = client.get_merge_request(iid)
    refs = mr.get("diff_refs") or {}
    head_sha = mr.get("sha") or refs.get("head_sha")
    if not head_sha:
        raise ConfigError("merge request has no diff refs yet; try again once GitLab has computed the diff")
    # diff_refs.start_sha is stale once the target branch moves; use its current tip for the rules.
    target_sha = client.get_branch_sha(mr["target_branch"])
    return check_review(root, target_sha, head_sha, mr["author"]["username"], approved_usernames(client.get_approvals(iid)))
