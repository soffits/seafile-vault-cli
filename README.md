# Seafile Vault CLI

Seafile Vault CLI is a secure, non-interactive command line tool for one Seafile library scoped by one repo token. It is built for agent and automation runtimes that need deterministic JSON, narrow permissions, explicit paths, and no interactive prompts.

The CLI is the primary interface. The optional MCP server exposes read-only tools for runtimes that can use MCP.

## Architecture And Security

- `src/seafile_vault_cli/client.py` owns Seafile protocol behavior and security checks.
- `src/seafile_vault_cli/cli.py` owns command dispatch and JSON success/error envelopes.
- `src/seafile_vault_cli/metadata.py` owns grouped metadata commands and bounded JSON stdin parsing.
- `src/seafile_vault_cli/mcp_server.py` exposes read-only MCP tools only.
- `src/seafile_vault_cli/lock_registry.py` tracks durable local lock state without storing secrets.

Security boundaries:

- `SEAFILE_REPO_TOKEN` is required and must scope exactly one library. Tokens are read from environment variables only, never argv.
- `SEAFILE_PERMISSION_MODE` defaults to `read_only`; write operations require `read_write` and mutation-specific confirmation where applicable.
- `SEAFILE_ACCOUNT_TOKEN` is optional and used only for account-token capabilities: history, current-library public share lifecycle, and thumbnail fetches.
- Repo and account authorization headers are isolated. Repo-token calls use `Bearer`; account-token calls use `Token`.
- Remote paths must be absolute normalized POSIX paths. Relative paths, `.`, `..`, duplicate slashes, ASCII control characters, unsafe root operations, and unsafe returned links are rejected.
- Download and upload links are same-origin validated. Token-bearing upload/download URLs, authorization headers, repo tokens, account tokens, raw revoke tokens, and passwords are redacted from errors and sanitized results.
- Agent-facing list/search/metadata outputs strip repo IDs, owner emails, modifier emails, lock owners, tokens, passwords, and other unnecessary internals while keeping required view/tag/record IDs.
- Thumbnail download never falls back to the original file. Missing or invalid thumbnail routes fail explicitly.
- Tests must not contact live Seafile or GitHub.

## Installation

Install from the public source:

```bash
pipx install git+https://github.com/soffits/seafile-vault-cli.git
```

For a local checkout:

```bash
git clone https://github.com/soffits/seafile-vault-cli.git
cd seafile-vault-cli
uv sync --extra dev
uv run seafile-vault --help
```

Install MCP support only when needed:

```bash
pipx install 'git+https://github.com/soffits/seafile-vault-cli.git#egg=seafile-vault-cli[mcp]'
uv sync --extra dev --extra mcp
uv run seafile-vault-mcp
```

## Configuration

Required:

```bash
export SEAFILE_SERVER_URL="https://seafile.example.com"
export SEAFILE_REPO_TOKEN="repo-token-for-one-library"
export SEAFILE_PERMISSION_MODE="read_only"
```

Optional:

```bash
export SEAFILE_ACCOUNT_TOKEN="account-token-for-optional-capabilities"
export SEAFILE_MAX_READ_SIZE=1048576
export SEAFILE_MAX_WRITE_SIZE=10485760
export SEAFILE_REQUEST_TIMEOUT=30
export SEAFILE_UPLOAD_TIMEOUT=3600
export SEAFILE_UPLOAD_CHUNK_SIZE=64MiB
export SEAFILE_UPLOAD_DIRECT_IP="203.0.113.10"
```

Use `read_only` for inspection and short-lived `read_write` only for sessions that must mutate remote state.

## Profiles

`seafile-library` selects one named profile from `~/.config/seafile-vault/libraries` or `SEAFILE_LIBRARY_CONFIG_DIR`:

```bash
seafile-library --list
seafile-library docs repo-info
seafile-library docs search / --name '*.md'
seafile-library docs metadata views list
```

A profile named `docs` maps only to `docs.env`. Profile files are strict UTF-8 `KEY=VALUE` files, without shell evaluation. The launcher rejects traversal, control characters, symlinks, unsupported keys, duplicate keys, malformed lines, NUL bytes, insecure directory permissions, and env files readable or writable by group/other users. Supported Seafile keys are `SEAFILE_SERVER_URL`, `SEAFILE_REPO_TOKEN`, `SEAFILE_ACCOUNT_TOKEN`, `SEAFILE_PERMISSION_MODE`, size/time limits, chunk settings, and direct-origin upload IP.

## Core Commands

Read-only examples:

```bash
seafile-vault repo-info
seafile-vault list /
seafile-vault list / --recursive --type file --compact
seafile-vault search / --name '*.md' --type file --max-results 50
seafile-vault stat /docs/note.md
seafile-vault download /docs/note.md ./note.md
seafile-vault download-link /docs/note.md
```

Write examples:

```bash
SEAFILE_PERMISSION_MODE=read_write seafile-vault mkdir /exports
SEAFILE_PERMISSION_MODE=read_write seafile-vault mkdir /exports/2026/august --parents
SEAFILE_PERMISSION_MODE=read_write seafile-vault rename /drafts/note.md final.md
SEAFILE_PERMISSION_MODE=read_write seafile-vault move /drafts/final.md /exports
SEAFILE_PERMISSION_MODE=read_write seafile-vault copy /docs/note.md /exports
SEAFILE_PERMISSION_MODE=read_write seafile-vault copy /docs/project /exports --dir
SEAFILE_PERMISSION_MODE=read_write seafile-vault delete /exports/final.md
```

File copies use the single-file operation and preserve the server's conflict-renamed destination name. Directory copies use Seafile's synchronous single-item batch-copy route; copying into the source directory, the same parent, or a descendant is rejected locally.

Uploads:

```bash
SEAFILE_PERMISSION_MODE=read_write seafile-vault upload ./local.md /docs/local.md
SEAFILE_PERMISSION_MODE=read_write seafile-vault upload ./local.md /docs/local.md --overwrite
SEAFILE_PERMISSION_MODE=read_write seafile-vault upload ./large.zip /exports/large.zip --chunked
SEAFILE_PERMISSION_MODE=read_write seafile-vault upload ./large.zip /exports/large.zip --chunk-size 64MiB
```

The upload path must include the target filename. Uploads open the local source once with symlink-safe flags, verify a regular file descriptor, check `SEAFILE_MAX_WRITE_SIZE`, and stream from that descriptor. Native chunked upload bounds each multipart request below `100000000` bytes and verifies final file size before reporting success. Direct-origin upload is optional and environment-specific; use it only after validating routing, TLS, firewall, and server limits.

## Locks

Locks are finite server locks plus local tracking records. Every successful `lock` must be paired with `unlock`, preferably in `finally` or a shell `trap`:

```bash
SEAFILE_PERMISSION_MODE=read_write seafile-vault locks
SEAFILE_PERMISSION_MODE=read_write seafile-vault lock /docs/note.md --expires 900
trap 'SEAFILE_PERMISSION_MODE=read_write seafile-vault unlock /docs/note.md >/dev/null || true' EXIT
# edit/upload the protected file here
SEAFILE_PERMISSION_MODE=read_write seafile-vault unlock /docs/note.md
trap - EXIT
SEAFILE_PERMISSION_MODE=read_write seafile-vault locks
```

Use `locks --prune` only after a `locks` audit proves records are stale because the server reports unlocked or the file is gone. Do not leave locks behind for other clients.

Normal `unlock` refuses paths absent from the local registry so it cannot silently release a lock created by another client. If the registry was genuinely lost, first verify the exact path and lock ownership, then use the explicit recovery form `unlock PATH --force-untracked --confirm`.

## History, Restore, Shares, And Thumbnails

History requires `SEAFILE_ACCOUNT_TOKEN`:

```bash
seafile-vault history library --page 1 --per-page 100
seafile-vault history file /docs/note.md --cursor 0123456789abcdef0123456789abcdef01234567
```

Restore uses the repo token, requires `read_write`, and requires confirmation:

```bash
SEAFILE_PERMISSION_MODE=read_write seafile-vault restore file /docs/note.md --commit 0123456789abcdef0123456789abcdef01234567 --confirm
SEAFILE_PERMISSION_MODE=read_write seafile-vault restore dir /docs/archive --commit 0123456789abcdef0123456789abcdef01234567 --confirm
```

Public share list/create/revoke use `SEAFILE_ACCOUNT_TOKEN`. Creation requires finite expiry and explicit public confirmation; revoke reads the raw token from stdin and redacts it from errors:

```bash
seafile-vault share list
SEAFILE_PERMISSION_MODE=read_write seafile-vault share create /docs/note.md --expire-days 7 --permission view-only --confirm-public
printf '%s\n' "$SHARE_TOKEN" | SEAFILE_PERMISSION_MODE=read_write seafile-vault share revoke --token-stdin --confirm
```

Thumbnails use the explicit account-token thumbnail API to generate and fetch the server preview without downloading the original file. The output is a local mode-0600 image file suitable for agent vision tools:

```bash
seafile-vault thumbnail /images/diagram.png ./diagram-thumb.png --size 256 --overwrite
```

## Metadata

Metadata commands use Seafile v13 repo-token metadata routes. Reads work in `read_only`; mutations require `read_write`, `--confirm`, and bounded `--json-stdin` for server-native bodies. JSON stdin must be exactly one UTF-8 JSON object, with no trailing data, and is capped at 262144 bytes.

Read examples:

```bash
seafile-vault metadata views list
seafile-vault metadata views get VIEW_ID
seafile-vault metadata records list VIEW_ID --start 0 --limit 100
seafile-vault metadata tags status
seafile-vault metadata tags list --start 0 --limit 100
seafile-vault metadata tags files TAG_ID
printf '%s\n' '{"tags_ids":["TAG_ID"]}' | seafile-vault metadata files tags --json-stdin
```

Mutation examples:

```bash
printf '%s\n' '{"records_data":[{"record_id":"REC_ID","record":{"name":"Updated"}}]}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata records update --json-stdin --confirm
printf '%s\n' '{"name":"Review","type":"table","data":{}}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata views create --json-stdin --confirm
printf '%s\n' '{"view_id":"VIEW_ID","view_data":{"name":"Review 2"}}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata views update --json-stdin --confirm
printf '%s\n' '{"view_id":"VIEW_ID"}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata views delete --json-stdin --confirm
SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata tags enable --lang en --confirm
SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata tags disable --confirm
printf '%s\n' '{"tags_data":[{"name":"Important"}]}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata tags create --json-stdin --confirm
printf '%s\n' '{"tag_ids":["TAG_ID"]}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata tags delete --json-stdin --confirm
printf '%s\n' '{"file_tags_data":[{"record_id":"REC_ID","tags":["TAG_ID"]}]}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata files assign-tags --json-stdin --confirm
printf '%s\n' '{"target_tag_id":"TAG_ID","merged_tags_ids":["OLD_TAG_ID"]}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata tags merge --json-stdin --confirm
```

If metadata or tags are disabled for the library, commands return a structured `capability` error with an actionable message. Routes that a deployment does not expose are reported as unsupported capabilities rather than emulated through arbitrary URL calls.

## MCP

`seafile-vault-mcp` exposes safe read tools only: repo info, directory list, recursive name search, UTF-8 text read, same-origin download link, library/file history, current-library share list, metadata views list/get, metadata records list, metadata tags status/list, and tag files. It does not expose share creation/revocation, restore, lock/unlock, uploads, writes, deletes, moves, renames, or metadata mutations.

## JSON Contract

Successful commands write one compact JSON object to stdout:

```json
{"data":{"repo_name":"Example"},"ok":true}
```

Errors write one compact JSON object to stderr:

```json
{"error":{"code":"permission_denied","message":"write operation blocked: set SEAFILE_PERMISSION_MODE=read_write"},"ok":false}
```

Exit codes are stable: `0` success, `2` usage, `3` configuration or unsupported capability, `4` permission mode, `5` path/link/local input security, and `6` Seafile/remote/size/local lock failures.

## Development

```bash
uv sync --extra dev --extra mcp
uv run ruff check src tests pyproject.toml
uv run pytest
uv build
```
