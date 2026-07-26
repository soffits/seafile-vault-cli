# Contributing

Thank you for improving Seafile Vault CLI.

## Development

```bash
uv sync --extra dev
uv run ruff check .
uv run pytest
uv build
```

Keep changes small, documented, and covered by tests. Public repository text, code comments, and tests must be English-only and must not contain real private hosts, IPs, repo tokens, repo IDs, library names, or deployment paths.

## Security

Do not add token CLI arguments. Secrets must remain environment-only and must be redacted from errors, logs, and JSON results.
