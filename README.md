# tripwire

Protect blocks of code in Git. A protected block can only be changed by its
owner or a leader, or by someone whose change an authorized person approved.
Works from a local pre-commit check, a self-hosted `pre-receive` hook, or as a
required check on GitHub, GitLab and Gitea / Forgejo.

## Quick start

1. Mark a block in any language, inside a comment:

   ```python
   # @lock-begin billing
   RATE = 5
   # @lock-end billing
   ```

2. Create `.tripwire/locks.json` (see `locks.example.json`):

   ```json
   {
     "leaders": ["alice"],
     "locks": [
       {"id": "billing", "owners": ["bob"], "approvers": ["carol"]},
       {"id": "prod-config", "owners": ["bob"], "paths": ["config/prod/", "*.pem"]}
     ]
   }
   ```

3. Check a change:

   ```bash
   pip install tripwire
   tripwire preflight --actor dave        # uncommitted changes vs HEAD
   ```

   Output: `tripwire: BLOCKED` with `block 'billing' in app.py is locked; ask:
   alice, bob, carol`, exit code 1.

## Concepts

- Blocks are marked with `@lock-begin <id>` / `@lock-end <id>`; files and
  folders are locked with path patterns (`dir/` prefix or glob).
- Owners and leaders may edit freely. Anyone else needs an approval from an
  owner, an approver or a leader. You cannot approve your own change.
- Approvals are bound to the exact before/after content of the protected
  block (a SHA-256 digest). Edit the code again and the approval is void.
- Rules are always read from the **base** revision (the target branch), so a
  change cannot rewrite the rules that judge it. Changing the rules file is
  leaders-only and cannot be approved.
- Whitespace-only edits are ignored. Deleting markers counts as a change.
  Unclosed blocks extend to end of file. A marker whose id is missing from the
  rules is leaders-only.

## Commands

```bash
tripwire preflight --actor alice                              # uncommitted changes vs HEAD
tripwire check --base origin/main --head HEAD --actor alice   # a commit range
tripwire approve --base origin/main --head HEAD --approver carol  # local approvals file
tripwire preflight --staged                                   # staged changes only
tripwire install-hook                                         # local pre-commit hook
tripwire pre-receive                                          # server hook, reads stdin
tripwire github-check | gitlab-check | gitea-check            # pull / merge requests
```

Exit codes: 0 allowed, 1 blocked, 2 error (fails closed).

## Local early warning

`tripwire install-hook` installs a `pre-commit` hook that checks staged changes
and refuses the commit when a protected block is touched without permission
(or use `.pre-commit-hooks.yaml` with the pre-commit framework). Your Git
identity (`git config user.email`, or `TRIPWIRE_ACTOR`) must match a name in
`locks.json`. This is a convenience: `git commit --no-verify` skips it, so the
server-side or CI check below remains the real gate. Nothing can stop someone
from editing files in their own clone; tripwire stops unapproved changes from
landing on protected branches.

## Platforms

| Platform | Enforce with | Approvals from | Verified |
|---|---|---|---|
| Self-hosted Git | `hooks/pre-receive` | `.tripwire/approvals.json` | real git repos |
| GitHub | required check, `templates/github-actions.yml` | PR reviews | real GitHub |
| GitLab | required pipeline, `templates/gitlab-ci.yml` | MR approvals | simulated API only |
| Gitea / Forgejo | required check, `templates/gitea-actions.yml` | PR reviews | simulated API only |

On hosted services, also forbid direct pushes to the protected branch and add a
path lock for the CI configuration, otherwise a PR can delete the check.

**Self-hosted Git.** Copy `hooks/pre-receive` into the bare repo and set
`TRIPWIRE_ACTOR` from your server's authenticated user.

**GitHub.** Only a reviewer's latest review counts; it must be `APPROVED` on
the PR's current head commit, so a new push voids it. Reviewer logins are
matched to names in `locks.json` case-insensitively; teams are not supported.

**GitLab.** Store a `read_api` project access token as `GITLAB_TOKEN`. GitLab's
approvals endpoint is not bound to a commit, so enable "Remove all approvals
when commits are added to the source branch"; tripwire cannot verify it.

**Gitea / Forgejo.** Enable "Dismiss stale approvals". Stale and dismissed
reviews are ignored. The API base comes from `--gitea-url`, `GITEA_API_URL`,
`GITHUB_API_URL` or `GITHUB_SERVER_URL`.

## Architecture

- `engine.py`: platform-neutral core (diff + actor + rules + approvals -> decision)
- `review.py`: shared pull / merge request check used by the platform adapters
- `github.py`, `gitlab.py`, `gitea.py`: API clients and approval mapping
- `approvals.py`: local approvals file
- `gitio.py`, `cli.py`: Git access and command line

## Limits

- Identity comes from `--actor` / `TRIPWIRE_ACTOR` locally; it is only as
  trustworthy as whatever sets it. On hosted platforms it is the PR author.
- The local approvals file is trust-based: anyone able to commit could write an
  entry naming an approver. Use platform approvals for real deployments.
- On every platform, people who can edit branch protection or CI settings are
  trusted; tripwire cannot stop an admin from switching the rule off.
- Pushes with several authors are checked as one cumulative diff by the pusher.
- Whitespace-insensitive comparison also ignores indentation changes.
- Not yet: platform teams, Bitbucket, Azure DevOps, Gerrit, CODEOWNERS import.

## Development

```bash
pip install -e .[dev]
pytest
```

## License

MIT
