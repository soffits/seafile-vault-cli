# AGENTS.md

This repository builds a secure, non-interactive Python CLI and optional MCP server for one token-scoped Seafile library. Core Seafile behavior belongs in `src/seafile_vault_cli/client.py`; command parsing and JSON envelopes belong in `src/seafile_vault_cli/cli.py`; grouped metadata command parsing and bounded JSON stdin belong in `src/seafile_vault_cli/metadata.py`; MCP wrappers belong in `src/seafile_vault_cli/mcp_server.py`; durable local lock state belongs in the lock registry module.

Use `uv run ruff check src tests pyproject.toml` for linting and `uv run pytest` for tests. Keep changes typed, focused, and consistent with the existing JSON error model. Prefer stdlib facilities unless a dependency is clearly necessary.

Security boundaries: never persist repo tokens, account tokens, authorization headers, upload/download links, raw share revoke tokens, passwords, or live Seafile secrets. Do not contact live Seafile or GitHub from tests. Preserve path validation, same-origin link validation, read-only mode, metadata capability mapping, thumbnail no-fallback behavior, and redaction rules. MCP must remain read-only.

Repository text must be English only. Do not include assistant provenance, private persona mechanics, generated-by notes, or hidden process descriptions. Commit messages, when requested, use Conventional Commits. The project license is AGPL-3.0-only.
