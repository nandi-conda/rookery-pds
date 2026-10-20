# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The Worker -> Durable Object call boundary.

Each call is one method name plus keyword arguments, sent as a JSON string
(bytes tagged so they survive), and answered with {"ok": result} or
{"err": [kind, message]}. Keeping the boundary a plain string makes it the
same in production and in tests, and keeps the DO the only place the
account's keys and repo exist.
"""

import base64
import json

from .errors import XrpcError
from .repo import RepoError
from .spaces.account import SPACE_METHODS

BYTES_TAG = "__bytes__"


def _tag(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {BYTES_TAG: base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, dict):
        return {key: _tag(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_tag(item) for item in value]
    return value


def _untag(value):
    if isinstance(value, dict):
        if len(value) == 1 and BYTES_TAG in value:
            return base64.b64decode(value[BYTES_TAG])
        return {key: _untag(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_untag(item) for item in value]
    return value


def encode(value) -> str:
    return json.dumps(_tag(value), separators=(",", ":"), ensure_ascii=False)


def decode(text: str):
    return _untag(json.loads(text))


class RemoteError(Exception):
    """An unexpected failure inside a Durable Object."""


# Errors that cross the boundary as themselves; anything else is a RemoteError.
_KNOWN = {"RepoError": RepoError}


async def serve(target, allowed: frozenset, request: str) -> str:
    """Run one call against `target` (inside the DO) and envelope the outcome."""
    call = decode(request)
    method = call["method"]
    if method not in allowed:
        return encode({"err": ["RemoteError", f"unknown method {method}"]})
    try:
        result = await getattr(target, method)(**call.get("args", {}))
    except XrpcError as exc:
        return encode({"err": ["XrpcError", [exc.name, exc.message, exc.status]]})
    except RepoError as exc:
        return encode({"err": ["RepoError", str(exc)]})
    return encode({"ok": result})


def request(method: str, args: dict) -> str:
    return encode({"method": method, "args": args})


def unwrap(response: str):
    outcome = decode(response)
    if "err" in outcome:
        kind, message = outcome["err"]
        if kind == "XrpcError":
            raise XrpcError(*message)
        raise _KNOWN.get(kind, RemoteError)(message)
    return outcome["ok"]


ACCOUNT_METHODS = frozenset({
    "init_account", "sign_with_rotation_key", "set_handle", "sign_service_auth", "get_state",
    "account_status", "get_latest_commit", "get_repo_status", "describe_repo", "has_published", "get_record",
    "list_records", "create_record", "put_record", "delete_record", "apply_writes", "insert_blob",
    "list_blobs", "get_blocks", "export_repo", "export_account", "import_account", "takedown",
}) | SPACE_METHODS


class AccountClient:
    """`await client.create_record(collection=..., ...)` -> the DO's Account method."""

    def __init__(self, send):
        self._send = send  # async (request_str) -> response_str

    def __getattr__(self, method: str):
        if method not in ACCOUNT_METHODS:
            raise AttributeError(method)

        async def call(**args):
            return unwrap(await self._send(request(method, args)))
        return call
