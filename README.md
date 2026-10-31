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
   pip install tripwire-git
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

## Rules file reference

```json
{
  "whitespace": "ignore",
  "groups": {"finance": ["bob", "carol"], "all": ["@finance", "dave"]},
  "leaders": ["alice", "@org/platform"],
  "locks": [
    {"id": "billing", "owners": ["@finance"], "approvers": ["@all"]},
    {"id": "py-core", "owners": ["bob"], "paths": ["src/core/"], "whitespace": "indent"}
  ]
}
```

- `groups`: reusable lists, referenced as `@name` (groups may contain groups).
- `@org/team`: a platform team. The GitHub adapter resolves it through the API
  (the token needs `read:org`); other adapters leave it unresolved, so it never
  matches anybody. `tripwire validate` warns about this.
- `whitespace`: `ignore` (default) treats re-indenting as no change; `indent`
  keeps leading whitespace significant, for Python and similar. Set it globally
  or per lock. Trailing whitespace and blank lines never count.
- `paths`: `dir/` prefix or a glob (`*` also matches `/`).

Helpers:

```bash
tripwire validate                                     # lint the rules against the repository
tripwire import-codeowners --leader alice --write     # start from an existing CODEOWNERS
```

`import-codeowners` turns every CODEOWNERS pattern into a path lock. CODEOWNERS
applies "last match wins"; tripwire locks are additive, so it is stricter only
where a later pattern deliberately narrows an earlier one. Sections and email
owners are skipped with a warning. Set `leaders` before relying on the result.

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

## AI coding agents (Claude Code)

Stop an AI agent from changing protected code *before* it touches the disk:

```bash
tripwire install-claude-hook      # adds a PreToolUse hook to .claude/settings.json
```

The agent acts as its own identity (`TRIPWIRE_AI_ACTOR`, default `ai-agent`),
which is not an owner unless you list it. When it tries to `Edit`, `MultiEdit`
or `Write` a protected block, the call is refused with a message naming who may
approve it, and the request is recorded. A human then approves that exact
change **from an interactive terminal**; `grant` shows the request and makes
the person type the approver's name to confirm (a pseudo-terminal alone is not
trusted):

```bash
tripwire pending                                  # what was blocked
tripwire grant <id> --approver anna               # the agent can now retry the same edit
```

The approval is bound to the exact before/after content, so a different edit
is blocked again. To let the agent edit a block freely, list its identity as an
owner of that lock. Rules are read from the committed version (`HEAD`), and the
agent cannot edit the rules or approvals files, run `tripwire grant`, or touch
those files through `Bash`.

Limits: shell commands that rewrite files (`sed -i`, redirects, scripts) are not
inspected, so keep the pre-commit hook and the server / CI check as backstops.
`grant` trusts whoever runs it in a terminal; a person with shell access can
also edit `.tripwire/approvals.json` by hand. Verified with simulated hook
payloads and end to end with a live Claude Code 2.1 session: the edit was
refused with the message shown to the agent, a human `grant` let the identical
retry through, and the agent's own attempt to run `tripwire grant` did not
approve anything.

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
matched to names in `locks.json` case-insensitively; `@org/team` entries are
resolved through the API.

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
- By default re-indenting is not a change; set `"whitespace": "indent"` for
  languages where indentation matters.
- Platform teams (`@org/team`) are resolved on GitHub only (simulated API tests;
  not run against a real organization).
- Not yet: GitLab groups and Gitea teams, Bitbucket, Azure DevOps, Gerrit.

## Development

```bash
pip install -e .[dev]
pytest
```

## License

MIT
