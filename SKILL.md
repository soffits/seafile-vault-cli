---
name: seafile-vault-cli
description: Use when operating one token-scoped Seafile library through Seafile Vault CLI or its optional read-only MCP server.
version: 0.4.0
author: Sakina
license: AGPL-3.0
metadata:
  hermes:
    tags:
      - seafile
      - cli
      - vault
      - mcp
      - secure-upload
      - metadata
---

# Seafile Vault CLI

## Purpose

Use this skill for one configured Seafile library scoped by `SEAFILE_REPO_TOKEN`. The CLI is deterministic JSON-first automation for listing, searching, reading, downloading, uploading, locking, history/share/thumbnail workflows, and Seafile v13 metadata views/records/tags.

The MCP server is read-only. Use the CLI for any mutation.

## Safety Rules

- Never put repo tokens, account tokens, authorization headers, upload links, download links, share revoke tokens, or passwords in prompts, argv, logs, docs, tests, or shell history.
- Keep `SEAFILE_PERMISSION_MODE=read_only` unless the exact command needs mutation.
- Use exact absolute vault paths only. Do not infer destructive targets from broad language.
- Do not contact live Seafile unless the user explicitly asked for an operation against their configured library.
- Do not use arbitrary URL or method calls. Use the named CLI commands only.
- Prefer `download` over `download-link` unless the caller explicitly needs the temporary bearer-like link.
- Public share creation must have finite expiry and `--confirm-public`; revocation must read the token from stdin and use `--confirm`.
- Restore requires `--confirm` and a 40-character commit ID.
- Metadata mutations require `read_write`, `--confirm`, and `--json-stdin` where documented.

## Lock Safety

Locks need extra care. Every successful `lock` must be followed by `unlock` in a `finally` block or shell `trap`. Always audit locks before and after work. Never leave locks behind.

Required shell pattern:

```bash
SEAFILE_PERMISSION_MODE=read_write seafile-vault locks
SEAFILE_PERMISSION_MODE=read_write seafile-vault lock /docs/note.md --expires 900
trap 'SEAFILE_PERMISSION_MODE=read_write seafile-vault unlock /docs/note.md >/dev/null || true' EXIT
# perform the protected edit/upload here
SEAFILE_PERMISSION_MODE=read_write seafile-vault unlock /docs/note.md
trap - EXIT
SEAFILE_PERMISSION_MODE=read_write seafile-vault locks
```

Required Python pattern:

```python
import subprocess

path = "/docs/note.md"
subprocess.run(["seafile-vault", "locks"], check=True)
subprocess.run(["seafile-vault", "lock", path, "--expires", "900"], check=True)
try:
    # edit or upload the protected file here
    pass
finally:
    subprocess.run(["seafile-vault", "unlock", path], check=False)
    subprocess.run(["seafile-vault", "locks"], check=False)
```

Use `locks --prune` only after a normal `locks` audit proves records are stale because the server reports unlocked or the file is gone:

```bash
SEAFILE_PERMISSION_MODE=read_write seafile-vault locks
SEAFILE_PERMISSION_MODE=read_write seafile-vault locks --prune
SEAFILE_PERMISSION_MODE=read_write seafile-vault locks
```

Do not prune active, expired-but-server-locked, or unknown-error records without operator confirmation.

Normal `unlock` refuses an untracked path. Use `unlock PATH --force-untracked --confirm` only for verified recovery after local registry loss; never use it merely to bypass the lock lifecycle.

## Setup

Required environment:

```bash
export SEAFILE_SERVER_URL="https://seafile.example.com"
export SEAFILE_REPO_TOKEN="repo-token-for-one-library"
export SEAFILE_PERMISSION_MODE="read_only"
```

Optional account token, only for history/share lifecycle/thumbnail fetch:

```bash
export SEAFILE_ACCOUNT_TOKEN="account-token-for-optional-capabilities"
```

Optional limits:

```bash
export SEAFILE_MAX_READ_SIZE=1048576
export SEAFILE_MAX_WRITE_SIZE=10485760
export SEAFILE_REQUEST_TIMEOUT=30
export SEAFILE_UPLOAD_TIMEOUT=3600
export SEAFILE_UPLOAD_CHUNK_SIZE=64MiB
export SEAFILE_UPLOAD_DIRECT_IP="203.0.113.10"
```

Use profiles when an operator provides named env files:

```bash
seafile-library --list
seafile-library docs list / --compact
seafile-library docs metadata views list
```

Profiles are strict env files under `~/.config/seafile-vault/libraries` or `SEAFILE_LIBRARY_CONFIG_DIR`. They may contain documented Seafile variables only and are read without shell evaluation.

## Read-Only Workflow

```bash
seafile-vault repo-info
seafile-vault list /
seafile-vault list / --recursive --type file --compact
seafile-vault search / --name '*.md' --type file --max-results 50
seafile-vault stat /docs/note.md
seafile-vault download /docs/note.md ./note.md
```

`list --compact` and `search` return agent-safe entries with normalized paths and no repo IDs, owner emails, modifier emails, lock owners, tokens, or internal database fields.

## Mutation Workflow

Use write mode only around the command that mutates state:

```bash
SEAFILE_PERMISSION_MODE=read_write seafile-vault mkdir /exports
SEAFILE_PERMISSION_MODE=read_write seafile-vault mkdir /exports/2026/august --parents
SEAFILE_PERMISSION_MODE=read_write seafile-vault rename /drafts/note.md final.md
SEAFILE_PERMISSION_MODE=read_write seafile-vault move /drafts/final.md /exports
SEAFILE_PERMISSION_MODE=read_write seafile-vault copy /docs/note.md /exports
SEAFILE_PERMISSION_MODE=read_write seafile-vault copy /docs/project /exports --dir
SEAFILE_PERMISSION_MODE=read_write seafile-vault delete /exports/final.md
```

Before delete, overwrite, move, rename, or a potentially large directory copy, list the exact parent and verify the target path. Directory copy refuses the same parent, the source itself, and source descendants. The CLI intentionally does not implement glob delete or recursive bulk mutation.

## Upload Workflow

```bash
SEAFILE_PERMISSION_MODE=read_write seafile-vault upload ./local.md /docs/local.md
SEAFILE_PERMISSION_MODE=read_write seafile-vault upload ./local.md /docs/local.md --overwrite
SEAFILE_PERMISSION_MODE=read_write seafile-vault upload ./large.zip /exports/large.zip --chunked
SEAFILE_PERMISSION_MODE=read_write seafile-vault upload ./large.zip /exports/large.zip --chunk-size 64MiB
```

The remote path must include the target filename. The CLI opens the local file once with symlink-safe flags, verifies a regular descriptor, checks size before network use, and streams from that descriptor. Native chunked upload is the preferred solution for large files and proxy body limits. Direct-origin upload is optional and should be used only after routing, TLS, firewall, and server limits are validated.

## History, Restore, Shares, And Thumbnails

History requires `SEAFILE_ACCOUNT_TOKEN`:

```bash
seafile-vault history library --page 1 --per-page 100
seafile-vault history file /docs/note.md --cursor 0123456789abcdef0123456789abcdef01234567
```

Restore requires repo-token write mode and explicit confirmation:

```bash
SEAFILE_PERMISSION_MODE=read_write seafile-vault restore file /docs/note.md --commit 0123456789abcdef0123456789abcdef01234567 --confirm
SEAFILE_PERMISSION_MODE=read_write seafile-vault restore dir /docs/archive --commit 0123456789abcdef0123456789abcdef01234567 --confirm
```

Share lifecycle requires `SEAFILE_ACCOUNT_TOKEN`; create/revoke also require write mode:

```bash
seafile-vault share list
SEAFILE_PERMISSION_MODE=read_write seafile-vault share create /docs/note.md --expire-days 7 --permission view-only --confirm-public
printf '%s\n' "$SHARE_TOKEN" | SEAFILE_PERMISSION_MODE=read_write seafile-vault share revoke --token-stdin --confirm
```

Thumbnail local-file workflow for agent vision:

```bash
seafile-vault thumbnail /images/diagram.png ./diagram-thumb.png --size 256 --overwrite
```

Thumbnail failures are explicit. The CLI never falls back to downloading the original file.

## Metadata Workflow

Metadata uses Seafile v13 repo-token metadata routes. Reads work in read-only mode:

```bash
seafile-vault metadata views list
seafile-vault metadata views get VIEW_ID
seafile-vault metadata records list VIEW_ID --start 0 --limit 100
seafile-vault metadata tags status
seafile-vault metadata tags list --start 0 --limit 100
seafile-vault metadata tags files TAG_ID
printf '%s\n' '{"tags_ids":["TAG_ID"]}' | seafile-vault metadata files tags --json-stdin
```

Mutations require `read_write`, `--confirm`, and JSON stdin for server-native bodies:

```bash
printf '%s\n' '{"records_data":[{"record_id":"REC_ID","record":{"name":"Updated"}}]}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata records update --json-stdin --confirm
printf '%s\n' '{"name":"Review","type":"table","data":{}}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata views create --json-stdin --confirm
printf '%s\n' '{"view_id":"VIEW_ID","view_data":{"name":"Review 2"}}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata views update --json-stdin --confirm
printf '%s\n' '{"view_id":"VIEW_ID"}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata views delete --json-stdin --confirm
SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata tags enable --lang en --confirm
SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata tags disable --confirm
printf '%s\n' '{"tags_data":[{"name":"Important"}]}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata tags create --json-stdin --confirm
printf '%s\n' '{"tags_data":[{"tag_id":"TAG_ID","tag":{"name":"Renamed"}}]}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata tags update --json-stdin --confirm
printf '%s\n' '{"tag_ids":["TAG_ID"]}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata tags delete --json-stdin --confirm
printf '%s\n' '{"link_column_key":"parent_links","row_id_map":{"TAG_ID":["PARENT_TAG_ID"]}}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata tag-links create --json-stdin --confirm
printf '%s\n' '{"file_tags_data":[{"record_id":"REC_ID","tags":["TAG_ID"]}]}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata files assign-tags --json-stdin --confirm
printf '%s\n' '{"target_tag_id":"TAG_ID","merged_tags_ids":["OLD_TAG_ID"]}' | SEAFILE_PERMISSION_MODE=read_write seafile-vault metadata tags merge --json-stdin --confirm
```

JSON stdin must be exactly one UTF-8 JSON object, no trailing data, capped at 262144 bytes. Metadata-disabled and tags-disabled responses return `capability` errors with actionable messages.

## MCP Workflow

Install the optional extra before running MCP:

```bash
pipx install 'git+https://github.com/soffits/seafile-vault-cli.git#egg=seafile-vault-cli[mcp]'
seafile-vault-mcp
```

MCP exposes read-only tools only: repo info, directory list, name search, text read, download link, library/file history, current-library share list, metadata views list/get, metadata records list, metadata tags status/list, and tag files. It does not expose share creation/revocation, restore, lock/unlock, writes, uploads, moves, renames, deletes, or metadata mutations.

## JSON Contract

Success goes to stdout:

```json
{"data":{"repo_name":"Example"},"ok":true}
```

Errors go to stderr:

```json
{"error":{"code":"permission_denied","message":"write operation blocked: set SEAFILE_PERMISSION_MODE=read_write"},"ok":false}
```

Exit codes: `0` success, `2` usage, `3` configuration or unsupported capability, `4` permission, `5` path/link/local-input security, `6` remote HTTP, Seafile, size-limit, or lock-registry failure.

## Verification

```bash
uv sync --extra dev --extra mcp
uv run ruff check src tests pyproject.toml
uv run pytest
uv build
uv run seafile-vault --help
uv run seafile-vault metadata --help
uv run seafile-library --help
```
