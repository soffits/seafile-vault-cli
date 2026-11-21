# AGENTS.md

This repository builds a secure, non-interactive Python CLI and optional MCP server for one Seafile library, reached with a repo token or with an account token plus library id. Core Seafile behavior belongs in `src/seafile_vault_cli/client.py`; the differences between the repo-token API and the regular user API (routes, parameter names, bodies) belong in `backend.py`; command parsing and JSON envelopes belong in `src/seafile_vault_cli/cli.py`; grouped metadata command parsing and bounded JSON stdin belong in `src/seafile_vault_cli/metadata.py`; MCP wrappers belong in `src/seafile_vault_cli/mcp_server.py`; durable local lock state belongs in the lock registry module.

Use `uv run ruff check src tests pyproject.toml` for linting and `uv run pytest` for tests. Keep changes typed, focused, and consistent with the existing JSON error model. Prefer stdlib facilities unless a dependency is clearly necessary.

Security boundaries: never persist repo tokens, account tokens, authorization headers, upload/download links, raw share revoke tokens, passwords, or live Seafile secrets. Do not contact live Seafile or GitHub from tests. Preserve path validation, same-origin link validation, read-only mode, metadata capability mapping, thumbnail no-fallback behavior, and redaction rules. MCP must remain read-only.

Repository text is English only. Commit messages use Conventional Commits. The project license is AGPL-3.0-or-later.

## Git

- PR titles are Conventional Commit subjects (`feat: ...`, `fix(scope): ...`), because a squash merge makes the title the commit on the default branch; CI checks it.
- Versions follow semver, and the bump comes from the commit types since the last tag, not from feel: below 1.0, `feat` or a breaking change (`!` / `BREAKING CHANGE`) is a minor bump and `fix`/`perf` a patch; from 1.0, breaking is major, `feat` minor, `fix` patch; docs/ci/chore/test alone need no release. The release check (`.github/workflows/release-check.yml`, `.github/scripts/release-bump-check.py`) fails a tag whose bump is too small; run the script with the new version before tagging.
