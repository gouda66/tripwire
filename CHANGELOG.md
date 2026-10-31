# Changelog

## Unreleased

- AI agent guard: `install-claude-hook`, `claude-hook`, `pending`, `grant`.
  A Claude Code PreToolUse hook blocks edits to protected blocks before they
  reach the disk; a human approves the exact change with `grant`.

## 0.1.0

First release.

- Core engine: block markers and path locks, owners / approvers / leaders,
  content-bound approvals, rules read from the base revision.
- CLI: `preflight` (also `--staged`), `check`, `approve`, `install-hook`, `pre-receive`.
- Platform adapters: `github-check` (verified on real GitHub), `gitlab-check`
  and `gitea-check` (simulated API only).
- CI templates for GitHub Actions, GitLab CI and Gitea / Forgejo Actions.
