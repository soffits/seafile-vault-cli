---
name: seafile-vault-cli
description: Use when operating one token-scoped Seafile library through Seafile Vault CLI or its optional MCP server.
version: 0.1.0
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
---

# Seafile Vault CLI

## Overview

Seafile Vault CLI is a non-interactive command line tool for exactly one Seafile library through a scoped repo token. It is designed for agent runtimes that need deterministic JSON, narrow permissions, explicit paths, and safe local-file upload behavior.

The optional MCP server exposes the same narrow operations, but the CLI is the primary interface and does not require MCP.

## When to Use

- Inspect metadata for one configured library.
- List explicit directories and read explicit files within size limits.
- Generate same-origin download links returned by Seafile.
- Create, rename, move, delete, write, or upload explicit paths after enabling `read_write` for that process.
- Upload large files with native Seafile multi-request chunked/resumable upload through the normal upload link.
- Use direct-origin upload only as an optional fallback when the operator has already validated routing, TLS, firewall, and server upload limits.

## When Not to Use

- Do not use for multiple libraries, account-wide automation, or admin operations.
- Do not use for glob delete, recursive bulk mutation, or unreviewed destructive cleanup.
- Do not pass repo tokens on argv or embed secrets in prompts, logs, docs, tests, or shell history.
- Do not use direct-origin upload unless the origin IP and upload path are approved for that environment.

## Setup

Install current public source from GitHub:

```bash
pipx install git+https://github.com/soffits/seafile-vault-cli.git
```

Install MCP support only when needed:

```bash
pipx install 'git+https://github.com/soffits/seafile-vault-cli.git#egg=seafile-vault-cli[mcp]'
```

Configure secrets through environment variables only:

```bash
export SEAFILE_SERVER_URL="https://seafile.example.com"
export SEAFILE_REPO_TOKEN="repo-token-for-one-library"
export SEAFILE_PERMISSION_MODE="read_only"
```

Optional limits and upload settings:

```bash
export SEAFILE_MAX_READ_SIZE=1048576
export SEAFILE_MAX_WRITE_SIZE=10485760
export SEAFILE_REQUEST_TIMEOUT=30
export SEAFILE_UPLOAD_TIMEOUT=3600
export SEAFILE_UPLOAD_CHUNK_SIZE=64MiB
export SEAFILE_UPLOAD_DIRECT_IP="203.0.113.10"
```

## JSON and Exit Contract

Successful commands write compact JSON to stdout:

```json
{"data":{"repo_name":"Example"},"ok":true}
```

Errors write compact JSON to stderr and return nonzero:

```json
{"error":{"code":"configuration","message":"SEAFILE_SERVER_URL is required"},"ok":false}
```

Exit codes are stable: `0` success, `2` usage, `3` configuration, `4` permission, `5` path/link/local-input security, and `6` remote HTTP, Seafile, or size-limit failure.

## Read-Only Workflow

Keep `SEAFILE_PERMISSION_MODE=read_only` for inspection:

```bash
seafile-vault repo-info
seafile-vault list /
seafile-vault download-link /path/file.md
```

Paths must be absolute normalized POSIX paths. Unicode is allowed. Relative paths, `.`, `..`, duplicate slashes, ASCII control characters, root file operations, and unsafe returned links are rejected.

## Mutation Workflow

Enable write mode only for the command or shell that needs it:

```bash
SEAFILE_PERMISSION_MODE=read_write seafile-vault mkdir /exports
SEAFILE_PERMISSION_MODE=read_write seafile-vault rename /inbox/draft.md final.md
SEAFILE_PERMISSION_MODE=read_write seafile-vault move /inbox/final.md /exports
SEAFILE_PERMISSION_MODE=read_write seafile-vault delete /exports/final.md
```

Uploads never overwrite unless `--overwrite` is explicit:

```bash
SEAFILE_PERMISSION_MODE=read_write seafile-vault upload ./local.md /inbox/local.md
SEAFILE_PERMISSION_MODE=read_write seafile-vault upload ./local.md /inbox/local.md --overwrite
```

## Upload Procedure

The CLI opens the local upload source once with symlink-safe flags, verifies the opened descriptor is a regular file, checks size before any network call, and streams from that same descriptor.

Native Seafile multi-request chunking is the primary Cloudflare-safe large-upload mechanism. Auto mode uses chunked upload for non-direct uploads larger than the effective chunk size and single-request upload for smaller files. The default chunk size is `67108864` bytes (64 MiB). Env and CLI text accepts plain bytes such as `67108864`, decimal units such as `64MB`, and binary units such as `64 MiB`; values are reported in result JSON as bytes. Configured or CLI chunk sizes are capped at `90000000` bytes, and every runtime multipart POST must have a complete request body smaller than `100000000` bytes after multipart overhead.

Chunked upload uses the normal upload link and multiple multipart POST requests with the same form fields (`file`, `parent_dir`, `replace`) plus `Content-Range` and `Content-Disposition` headers. The request `Content-Disposition` filename is exactly `attachment; filename="PERCENT_ENCODED_UTF8"` for Seafile's URI-unescape behavior; it does not use `filename*`.

Seafile merges and indexes the file after the final chunk. The CLI verifies `/api/v2.1/via-repo-token/file/?path=...` returns final file metadata with integer `size` exactly matching the local file before reporting chunked success, using only small bounded retries for final visibility lag.

Resume uses the server `uploadedBytes` endpoint when available. If that status endpoint returns `401`, `403`, `404`, `405`, or `501`, resume is treated as unsupported, chunking starts at offset 0, and the result reports `resume_supported:false`. Do not require `Accept-Ranges`; valid deployments can return `200` with `uploadedBytes` without that header.

Streaming is not chunking. A single streaming request avoids loading the whole local file into memory, but it can still exceed proxy or server request-body limits because it is one HTTP request. Chunked upload bounds each request body.

Useful upload flags:

```bash
SEAFILE_PERMISSION_MODE=read_write seafile-vault upload ./large.bin /exports/large.bin --chunked
SEAFILE_PERMISSION_MODE=read_write seafile-vault upload ./large.bin /exports/large.bin --chunk-size 64MiB
SEAFILE_PERMISSION_MODE=read_write seafile-vault upload ./large.bin /exports/large.bin --no-resume
SEAFILE_PERMISSION_MODE=read_write seafile-vault upload ./small.bin /exports/small.bin --single-request
```

Chunked result JSON includes safe metadata only: `upload_mode:"chunked"`, `chunk_size` in bytes, `chunks_sent`, `resumed_from`, `resume_supported`, `size`, `remote_path`, `overwrite`, `direct_origin:false`, and a sanitized final result. Token-bearing upload links and local paths are not returned.

## Direct-Origin Procedure

For approved large uploads, route only the upload connection to an explicit origin IP while preserving the Seafile upload-link hostname for HTTP Host and TLS/SNI:

```bash
SEAFILE_PERMISSION_MODE=read_write seafile-vault upload ./large.bin /exports/large.bin --direct-ip 203.0.113.10
```

Use direct origin only after confirming the origin accepts direct connections, the certificate matches the hostname, firewall rules allow the request, and server-side upload and timeout limits are high enough.

Direct-origin upload is an optional fallback, not a universal large-upload solution. In auto mode, configured direct-origin upload preserves the existing single-request direct behavior. Explicit `--chunked` with direct-origin routing is rejected with deterministic configuration JSON.

## Destructive-Action Safety

Destructive actions require an explicit command, an explicit path, and `read_write` mode. Root rename, root move, root delete, glob delete, and bulk delete are intentionally unsupported.

Before delete or overwrite, list the exact parent directory and verify the target path. Do not infer targets from broad user language; ask for the exact path when it is missing.

## Common Pitfalls

- A missing repo token or invalid permission mode returns a configuration JSON error.
- Write commands in `read_only` return a permission JSON error.
- Single-request uploads can fail at a CDN or reverse proxy before reaching Seafile if request body limits are lower than the file size.
- Use native chunked upload first for Cloudflare-safe large uploads; direct-origin is environment-specific fallback only.
- Direct-origin upload still uses the Seafile hostname for Host and TLS/SNI; do not replace the upload URL host with an IP.
- Token-bearing upload links are secrets; keep them out of argv, logs, issues, and examples.
- Install `seafile-vault-cli[mcp]` before running `seafile-vault-mcp`; without the extra it exits with deterministic configuration JSON on stderr.

## Verification Checklist

For development or release checks:

```bash
uv sync --extra dev
uv run ruff check .
uv run python -m pytest
uv build
uv run seafile-vault --help
uv run seafile-vault upload --help
```

Inspect built artifacts before publishing: the wheel should include `seafile_vault_cli/SKILL.md` and a complete license file, and the sdist should include root `SKILL.md` and `LICENSE`.
