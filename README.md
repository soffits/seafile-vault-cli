# Seafile Vault CLI

Seafile Vault CLI is a secure, non-interactive, agent-friendly command line tool for operating exactly one Seafile library through a scoped repo token.

The CLI is the primary product. The optional MCP server exposes the same narrow library operations for agent runtimes, but MCP is not required to use the project.

## Security Model

- Uses only `SEAFILE_REPO_TOKEN` with Seafile `/api/v2.1/via-repo-token/...` endpoints.
- Reads secrets only from environment variables. Repo tokens are never accepted as CLI arguments.
- Defaults to `SEAFILE_PERMISSION_MODE=read_only`; every mutating client, CLI, and MCP operation fails closed unless set to `read_write`.
- Validates remote paths as absolute normalized POSIX paths such as `/inbox/file.md`.
- Rejects `.`, `..`, duplicate slashes, ASCII control characters, relative paths, root rename, root move, and root delete.
- Does not implement glob or bulk delete.
- `search` is read-only, uses safe shell-style glob matching against names only, caps requested results at 1000, and fails instead of silently truncating overbroad matches.
- `seafile-library` selects one named library profile from `~/.config/seafile-vault/libraries` or `SEAFILE_LIBRARY_CONFIG_DIR` without shell evaluation.
- Never overwrites uploads unless `--overwrite` or `overwrite=True` is explicit.
- Constrains returned download and upload links to the configured `SEAFILE_SERVER_URL` origin. Temporary download and upload links are bearer-like secrets.
- `download` obtains temporary download links internally and never returns or logs them.
- Redacts repo tokens and token-bearing upload/download URLs from errors and result objects.
- Produces deterministic JSON: successful data on stdout, structured errors on stderr.
- Opens local upload sources once with symlink-safe flags, verifies the opened descriptor is a regular file, and uploads from that same descriptor for both single-request and chunked uploads.
- Downloads stream through the configured `httpx` client, enforce `SEAFILE_MAX_READ_SIZE`, write through a mode-0600 temp file in the destination directory, fsync, and atomically publish only after the full response succeeds.
- Plain `mkdir` rejects exact-name conflicts before creation and rejects Seafile implicit conflict renames. `mkdir --parents` walks path segments, skips exact existing directories, and fails on file collisions.

## Installation

Install the current public source from GitHub:

```bash
pipx install git+https://github.com/soffits/seafile-vault-cli.git
```

For a local clone or development checkout:

```bash
git clone https://github.com/soffits/seafile-vault-cli.git
cd seafile-vault-cli
pipx install --editable .
uv sync --extra dev
uv run seafile-vault --help
```

Install the optional MCP extra only when needed:

```bash
pipx install 'git+https://github.com/soffits/seafile-vault-cli.git#egg=seafile-vault-cli[mcp]'
uv sync --extra dev --extra mcp
uv run seafile-vault-mcp
```

## Environment

```bash
export SEAFILE_SERVER_URL="https://seafile.example.com"
export SEAFILE_REPO_TOKEN="repo-token-for-one-library"
export SEAFILE_PERMISSION_MODE="read_only"
```

Optional settings:

```bash
export SEAFILE_MAX_READ_SIZE=1048576
export SEAFILE_MAX_WRITE_SIZE=10485760
export SEAFILE_REQUEST_TIMEOUT=30
export SEAFILE_UPLOAD_TIMEOUT=3600
export SEAFILE_UPLOAD_CHUNK_SIZE=64MiB
export SEAFILE_UPLOAD_DIRECT_IP="203.0.113.10"
```

Use `read_only` for inspection and `read_write` only for sessions that must create, move, rename, delete, or upload content.

## CLI Usage

```bash
seafile-vault repo-info
seafile-vault list /
seafile-vault list / --recursive --type file --compact
seafile-vault search / --name '*.md' --type file --max-results 50
seafile-vault stat /inbox/note.md
seafile-vault download /inbox/note.md ./note.md
seafile-vault download /inbox/note.md ./note.md --overwrite
seafile-vault download-link /inbox/note.md
seafile-vault mkdir /exports
seafile-vault mkdir /exports/2026/july --parents
seafile-vault rename /inbox/draft.md final.md
seafile-vault rename /inbox/old-folder new-folder --dir
seafile-vault move /inbox/final.md /exports
seafile-vault move /inbox/new-folder /exports --dir
seafile-vault delete /exports/final.md
seafile-vault delete /exports/old-folder --recursive
seafile-vault upload ./local-note.md /inbox/local-note.md
seafile-vault upload ./local-note.md /inbox/local-note.md --overwrite
seafile-vault upload ./large-export.zip /exports/large-export.zip --chunked
seafile-vault upload ./large-export.zip /exports/large-export.zip --direct-ip 203.0.113.10
```

Upload syntax:

```bash
seafile-vault upload LOCAL_FILE REMOTE_PATH [--overwrite] [--chunked | --single-request] [--chunk-size SIZE] [--no-resume] [--direct-ip IP]
```

`REMOTE_PATH` must be an absolute vault file path including the target filename. The local path must be an existing regular file and not a final symlink. The CLI opens the local path once with safe flags, verifies that same descriptor with `fstat`, checks size against `SEAFILE_MAX_WRITE_SIZE` before any network call, and streams from the opened descriptor.

Upload modes:

- Auto mode is the default. Non-direct uploads larger than the effective chunk size use native Seafile chunked/resumable upload; smaller files use a single multipart request.
- `--chunked` forces native multi-request upload through the normal Seafile upload link. Each request is a bounded multipart POST with `Content-Range` and `Content-Disposition` headers.
- `--single-request` forces the legacy single multipart upload request.
- `--chunk-size SIZE` overrides `SEAFILE_UPLOAD_CHUNK_SIZE` for one upload. The default is `67108864` bytes (64 MiB). Values may be plain bytes such as `67108864`, decimal units such as `64MB`, or binary units such as `64 MiB`; units are parsed to bytes before validation. Values must be positive integers and are capped at `90000000` bytes. Every runtime multipart POST is also checked before network use and must have a complete request body smaller than `100000000` bytes after multipart overhead.
- `--no-resume` skips the server `uploadedBytes` query and starts chunked upload at offset 0.

Result JSON for path uploads includes `upload_mode`. Chunked results also include safe metadata such as `chunk_size` in bytes, `chunks_sent`, `resumed_from`, `resume_supported`, `size`, `remote_path`, `overwrite`, `direct_origin:false`, and a sanitized final Seafile result. Token-bearing upload links and local paths are never included.

Read syntax:

```bash
seafile-vault stat REMOTE_PATH
seafile-vault download REMOTE_PATH LOCAL_FILE [--overwrite]
seafile-vault list [REMOTE_DIR] [--recursive] [--type file|dir] [--compact]
seafile-vault search [REMOTE_DIR] --name GLOB [--type file|dir] [--max-results N] [--case-sensitive]
```

`stat` is file metadata only and rejects root. A missing file returns structured `remote_not_found` JSON instead of `null` success.

`download` is valid in `read_only` mode. It validates the same-origin temporary download link internally, streams to a unique temp file in the destination directory, checks `Content-Length` when present, enforces `SEAFILE_MAX_READ_SIZE` incrementally, and leaves any prior destination untouched on failure. The destination parent must be a real directory. Symlink destinations are always rejected. Existing destinations require `--overwrite`, and overwrite only replaces regular files.

Download result JSON contains only non-sensitive metadata:

```json
{"local_name":"note.md","overwrite":false,"remote_path":"/inbox/note.md","sha256":"...","size":123}
```

`list --compact` keeps only normalized agent-safe directory data and omits modifier emails, lock fields, IDs, repo IDs, repo names, and other Seafile internals. Its data shape is:

```json
{"count":1,"entries":[{"mtime":1720000000,"name":"note.md","size":123,"type":"file"}],"path":"/inbox"}
```

`search` validates `REMOTE_DIR`, performs the existing recursive directory listing for that one scoped library, and applies Python `fnmatch` shell-style glob matching to entry names only. It does not execute regular expressions. Results include only normalized full remote `path` plus available `name`, `type`, `size`, and `mtime`; repo IDs, modifier emails, locks, tokens, and other internals are omitted. The default limit is 100 results and the hard maximum is 1000. If more entries match than `--max-results`, the command returns a structured error instead of silently truncating.

## Library Profiles

`seafile-library` is an installed launcher for selecting named library env files:

```bash
seafile-library --list
seafile-library docs --help
seafile-library docs search / --name '*.md'
seafile-library docs list / --compact
```

Profiles live in `~/.config/seafile-vault/libraries` by default, overridable with `SEAFILE_LIBRARY_CONFIG_DIR`. A profile named `docs` must be exactly `docs.env` in that directory and contain strict UTF-8 `KEY=VALUE` lines without shell evaluation. Required keys are `SEAFILE_SERVER_URL` and `SEAFILE_REPO_TOKEN`. Optional documented Seafile keys are `SEAFILE_PERMISSION_MODE`, `SEAFILE_MAX_READ_SIZE`, `SEAFILE_MAX_WRITE_SIZE`, `SEAFILE_REQUEST_TIMEOUT`, `SEAFILE_UPLOAD_TIMEOUT`, `SEAFILE_UPLOAD_CHUNK_SIZE`, and `SEAFILE_UPLOAD_DIRECT_IP`.

The launcher rejects path traversal, control characters, symlinks, unsupported or duplicate keys, malformed lines, NUL bytes, insecure directory ownership/permissions, and env files readable/writable/executable by group or other users. `--list` returns compact JSON profile names only. Missing profiles return structured JSON with safe name suggestions only, never paths or env values.

Plain `mkdir /path` first lists the exact parent and fails if any file or directory already has the requested exact name. `mkdir --parents /a/b/c` returns concise metadata such as:

```json
{"created":["/a/b","/a/b/c"],"path":"/a/b/c","skipped":["/a"]}
```

## JSON Contract

Successful commands write one compact JSON object to stdout:

```json
{"data":{"repo_name":"Example"},"ok":true}
```

Errors write one compact JSON object to stderr and return a nonzero exit code:

```json
{"error":{"code":"permission_denied","message":"write operation blocked: set SEAFILE_PERMISSION_MODE=read_write"},"ok":false}
```

Exit codes:

- `0`: success
- `2`: CLI argument usage error from `argparse`
- `3`: configuration error
- `4`: permission mode blocked a write operation
- `5`: path, returned-link, or local-input security error
- `6`: remote HTTP, Seafile, or size-limit error

## Large Uploads, Chunking, And Direct Origin

Cloudflare Free and Pro plans commonly impose a 100 MB request body limit for proxied HTTP uploads. Uploads larger than that can fail before reaching Seafile even when Seafile itself is configured for larger files.

Native Seafile multi-request chunking is the primary Cloudflare-safe mechanism. It still uses the normal Seafile upload link, but splits a large file into multiple multipart POST requests below the proxy body cap. Each chunk request sends `Content-Disposition: attachment; filename="PERCENT_ENCODED_UTF8"`; the filename value is UTF-8 percent-encoded for Seafile's single URI-unescape pass and does not use `filename*`.

Seafile merges and indexes the file after the final chunk. After a normal final chunk response, the CLI verifies `/api/v2.1/via-repo-token/file/?path=...` returns file metadata with integer `size` exactly matching the local file before reporting success. If final visibility briefly lags, verification uses small bounded retries only.

Resume support uses Seafile's `uploadedBytes` status endpoint when available. Deployments that return `401`, `403`, `404`, `405`, or `501` for that status endpoint are treated as resume unsupported; chunking remains valid from byte 0 and reports `resume_supported:false`. A deployment does not need to send `Accept-Ranges` for this endpoint.

Streaming is not the same as chunking. Single-request uploads already stream from the validated local descriptor, but a streaming single request can still exceed a proxy or server request-body limit because it is one HTTP request. Chunked upload bounds each HTTP request body.

`--direct-ip IP` or `SEAFILE_UPLOAD_DIRECT_IP` can route only the upload connection to an explicit origin IP while preserving the upload-link hostname for HTTP `Host` and TLS/SNI. This can bypass a CDN request body limit only when the origin firewall, routing, certificate, Seafile/nginx upload limits, and request timeouts all permit direct-origin access.

Direct-origin upload is an optional fallback, not a universal large-upload solution. In auto mode, configured direct-origin upload preserves the existing single-request direct behavior. If `--chunked` is explicitly combined with direct-origin routing, the CLI rejects the command with deterministic configuration JSON instead of silently changing routing.

`SEAFILE_UPLOAD_TIMEOUT` is separate from `SEAFILE_REQUEST_TIMEOUT` and defaults to `3600` seconds. Normal uploads pass it to the upload `httpx` request. Direct-origin uploads pass it to curl as `max-time`, use a bounded connect timeout, and add a short subprocess timeout grace.

The direct-origin implementation validates the IP and same-origin upload URL, uses `curl --config -` with no `shell=True`, uploads from an inherited `/proc/self/fd/N` descriptor, keeps token-bearing URLs out of argv, and redacts token-bearing URLs from errors. Do not put real origin IPs, hosts, repo tokens, or upload links in source, docs, tests, shell history, or logs.

## Optional MCP

The optional MCP server is a narrow wrapper around the same client:

```bash
pipx install 'git+https://github.com/soffits/seafile-vault-cli.git#egg=seafile-vault-cli[mcp]'
seafile-vault-mcp
```

It exposes listing, metadata, text reads, same-origin download links, directory creation, rename, move, delete, text writes, and base64 uploads. It intentionally does not expose arbitrary local-path upload/download, because that would allow an MCP caller to read or write files on the host filesystem.

MCP mutations enforce `SEAFILE_PERMISSION_MODE=read_write` exactly like the CLI.

## Development

```bash
uv sync --extra dev
uv run ruff check .
uv run python -m pytest -p no:cacheprovider
uv build
uv run seafile-vault --help
uv run seafile-vault list --help
uv run seafile-vault search --help
uv run seafile-vault download --help
uv run seafile-vault upload --help
uv run seafile-library --help
uv run seafile-library --version
```

For release verification, inspect the wheel and sdist contents after `uv build`; do not claim live large-file success until a separate operator performs an upload through the target public hostname.

## License

AGPL-3.0. See `LICENSE`.
