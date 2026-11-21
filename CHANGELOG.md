# Changelog

## Unreleased

## 0.6.0

- Added account mode: set `SEAFILE_REPO_ID` with `SEAFILE_ACCOUNT_TOKEN` or `SEAFILE_ACCOUNT_TOKEN_FILE` instead of `SEAFILE_REPO_TOKEN`, and every command runs through Seafile's regular user API for that library. Library profiles accept `SEAFILE_REPO_ID`.

## 0.5.0

- Relicensed from AGPL-3.0-only to AGPL-3.0-or-later; earlier versions stay AGPL-3.0-only.
- Added `SEAFILE_ACCOUNT_TOKEN_FILE`, an alternative to `SEAFILE_ACCOUNT_TOKEN` that reads the account token from a file.
