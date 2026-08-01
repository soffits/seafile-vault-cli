from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .client import METADATA_DEFAULT_LIMIT, METADATA_JSON_MAX_BYTES, ConfigError, SeafileVaultClient


def add_metadata_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser], parser_class: type[argparse.ArgumentParser]
) -> None:
    p_metadata = subparsers.add_parser("metadata", help="Read and manage Seafile metadata views, records, and tags")
    metadata_sub = p_metadata.add_subparsers(dest="metadata_command", required=True, parser_class=parser_class)

    p_records = metadata_sub.add_parser("records", help="Read or update metadata records")
    records_sub = p_records.add_subparsers(dest="metadata_records_command", required=True, parser_class=parser_class)
    p_records_list = records_sub.add_parser("list", help="List records in one metadata view")
    p_records_list.add_argument("view_id", metavar="VIEW_ID")
    _add_pagination(p_records_list)
    _add_json_mutation(records_sub.add_parser("update", help="Update records from a records_data JSON object"))

    p_views = metadata_sub.add_parser("views", help="Read or manage metadata views")
    views_sub = p_views.add_subparsers(dest="metadata_views_command", required=True, parser_class=parser_class)
    views_sub.add_parser("list", help="List metadata views")
    p_views_get = views_sub.add_parser("get", help="Get one metadata view")
    p_views_get.add_argument("view_id", metavar="VIEW_ID")
    for name in ("create", "update", "delete", "duplicate", "move"):
        _add_json_mutation(views_sub.add_parser(name, help=f"{name.capitalize()} a metadata view using the server-native JSON body"))

    p_tags = metadata_sub.add_parser("tags", help="Read or manage metadata tags")
    tags_sub = p_tags.add_subparsers(dest="metadata_tags_command", required=True, parser_class=parser_class)
    tags_sub.add_parser("status", help="Check whether metadata tags are enabled")
    p_tags_list = tags_sub.add_parser("list", help="List metadata tags")
    _add_pagination(p_tags_list)
    p_tags_files = tags_sub.add_parser("files", help="List files linked to one tag")
    p_tags_files.add_argument("tag_id", metavar="TAG_ID")
    p_tags_enable = tags_sub.add_parser("enable", help="Enable metadata tags with a language code")
    p_tags_enable.add_argument("--lang", required=True, metavar="LANG")
    _add_confirm(p_tags_enable)
    _add_confirm(tags_sub.add_parser("disable", help="Disable metadata tags"))
    for name in ("create", "update", "delete", "merge"):
        _add_json_mutation(tags_sub.add_parser(name, help=f"{name.capitalize()} metadata tags using the server-native JSON body"))

    p_files = metadata_sub.add_parser("files", help="Read or assign file metadata tag mappings")
    files_sub = p_files.add_subparsers(dest="metadata_files_command", required=True, parser_class=parser_class)
    _add_json_stdin(files_sub.add_parser("tags", help="Query files for multiple tags using the server-native tags_ids JSON body"))
    _add_json_mutation(files_sub.add_parser("assign-tags", help="Assign tags to files or records using file_tags_data"))

    p_tag_links = metadata_sub.add_parser("tag-links", help="Manage metadata tag link mappings")
    tag_links_sub = p_tag_links.add_subparsers(dest="metadata_tag_links_command", required=True, parser_class=parser_class)
    for name in ("create", "update", "delete"):
        _add_json_mutation(tag_links_sub.add_parser(name, help=f"{name.capitalize()} tag links using link_column_key and row_id_map"))


def handle_metadata_command(client: SeafileVaultClient, args: argparse.Namespace) -> Any:
    if args.metadata_command == "records":
        return _handle_records(client, args)
    if args.metadata_command == "views":
        return _handle_views(client, args)
    if args.metadata_command == "tags":
        return _handle_tags(client, args)
    if args.metadata_command == "files":
        return _handle_files(client, args)
    if args.metadata_command == "tag-links":
        return _handle_tag_links(client, args)
    raise AssertionError(args.metadata_command)  # pragma: no cover


def _handle_records(client: SeafileVaultClient, args: argparse.Namespace) -> Any:
    if args.metadata_records_command == "list":
        return client.metadata_records_list(args.view_id, start=args.start, limit=args.limit)
    if args.metadata_records_command == "update":
        return client.metadata_records_update(_read_json_stdin_object())
    raise AssertionError(args.metadata_records_command)  # pragma: no cover


def _handle_views(client: SeafileVaultClient, args: argparse.Namespace) -> Any:
    if args.metadata_views_command == "list":
        return client.metadata_views_list()
    if args.metadata_views_command == "get":
        return client.metadata_view_get(args.view_id)
    body = _read_json_stdin_object()
    if args.metadata_views_command == "create":
        return client.metadata_views_create(body)
    if args.metadata_views_command == "update":
        return client.metadata_views_update(body)
    if args.metadata_views_command == "delete":
        return client.metadata_views_delete(body)
    if args.metadata_views_command == "duplicate":
        return client.metadata_views_duplicate(body)
    if args.metadata_views_command == "move":
        return client.metadata_views_move(body)
    raise AssertionError(args.metadata_views_command)  # pragma: no cover


def _handle_tags(client: SeafileVaultClient, args: argparse.Namespace) -> Any:
    if args.metadata_tags_command == "status":
        return client.metadata_tags_status()
    if args.metadata_tags_command == "list":
        return client.metadata_tags_list(start=args.start, limit=args.limit)
    if args.metadata_tags_command == "files":
        return client.metadata_tag_files(args.tag_id)
    if args.metadata_tags_command == "enable":
        return client.metadata_tags_enable(lang=args.lang)
    if args.metadata_tags_command == "disable":
        return client.metadata_tags_disable()
    body = _read_json_stdin_object()
    if args.metadata_tags_command == "create":
        return client.metadata_tags_create(body)
    if args.metadata_tags_command == "update":
        return client.metadata_tags_update(body)
    if args.metadata_tags_command == "delete":
        return client.metadata_tags_delete(body)
    if args.metadata_tags_command == "merge":
        return client.metadata_tags_merge(body)
    raise AssertionError(args.metadata_tags_command)  # pragma: no cover


def _handle_files(client: SeafileVaultClient, args: argparse.Namespace) -> Any:
    if args.metadata_files_command == "tags":
        return client.metadata_tags_files(_read_json_stdin_object())
    if args.metadata_files_command == "assign-tags":
        return client.metadata_file_tags_assign(_read_json_stdin_object())
    raise AssertionError(args.metadata_files_command)  # pragma: no cover


def _handle_tag_links(client: SeafileVaultClient, args: argparse.Namespace) -> Any:
    body = _read_json_stdin_object()
    if args.metadata_tag_links_command == "create":
        return client.metadata_tag_link_create(body)
    if args.metadata_tag_links_command == "update":
        return client.metadata_tag_link_update(body)
    if args.metadata_tag_links_command == "delete":
        return client.metadata_tag_link_delete(body)
    raise AssertionError(args.metadata_tag_links_command)  # pragma: no cover


def _read_json_stdin_object() -> dict[str, Any]:
    value = _read_json_stdin()
    if not isinstance(value, dict):
        raise ConfigError("JSON stdin must contain exactly one object")
    return value


def _read_json_stdin() -> Any:
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    raw = stream.read(METADATA_JSON_MAX_BYTES + 1)
    if isinstance(raw, str):
        if len(raw.encode("utf-8")) > METADATA_JSON_MAX_BYTES:
            raise ConfigError(f"JSON stdin exceeds {METADATA_JSON_MAX_BYTES} bytes")
        text = raw
    else:
        if len(raw) > METADATA_JSON_MAX_BYTES:
            raise ConfigError(f"JSON stdin exceeds {METADATA_JSON_MAX_BYTES} bytes")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConfigError("JSON stdin must be strict UTF-8") from exc
    if text == "":
        raise ConfigError("JSON stdin is required")
    decoder = json.JSONDecoder()
    try:
        value, end = decoder.raw_decode(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"JSON stdin is invalid: {exc.msg}") from exc
    if text[end:].strip():
        raise ConfigError("JSON stdin must contain exactly one JSON value with no trailing data")
    return value


def _add_pagination(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--start", type=_non_negative_int_arg("start"), default=0, metavar="N")
    parser.add_argument("--limit", type=_metadata_limit_arg, default=METADATA_DEFAULT_LIMIT, metavar="N")


def _add_json_stdin(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json-stdin", action="store_true", required=True, help="Read exactly one bounded JSON object from stdin")


def _add_confirm(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--confirm", action="store_true", required=True, help="Confirm metadata mutation")


def _add_json_mutation(parser: argparse.ArgumentParser) -> None:
    _add_json_stdin(parser)
    _add_confirm(parser)


def _non_negative_int_arg(name: str):
    def parse(value: str) -> int:
        try:
            parsed = int(value, 10)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{name} must be an integer") from exc
        if parsed < 0:
            raise argparse.ArgumentTypeError(f"{name} must be non-negative")
        return parsed

    return parse


def _metadata_limit_arg(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("limit must be an integer") from exc
    if parsed < 1 or parsed > METADATA_DEFAULT_LIMIT:
        raise argparse.ArgumentTypeError(f"limit must be between 1 and {METADATA_DEFAULT_LIMIT}")
    return parsed
