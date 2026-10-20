# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The OAuth scopes rookery grants: atproto, transition:generic, repo:<nsid>,
blob:*/*, rpc:<lxm>?aud=<did|*>, and space:<type>?... (see spaces.scopes)."""

import re
from urllib.parse import parse_qsl

from ..spaces.scopes import parse_space_scope
from ..syntax import is_valid_did, is_valid_nsid


def _parse_rpc(token: str) -> dict | None:
    body = token[len("rpc:"):]
    query_start = body.find("?")
    if query_start <= 0:
        return None
    lxm = body[:query_start]
    if lxm != "*" and not is_valid_nsid(lxm):
        return None
    params = parse_qsl(body[query_start + 1:], keep_blank_values=True)
    if any(key != "aud" for key, _ in params):
        return None
    aud = next((value for key, value in params if key == "aud"), None)
    if not aud or not (aud == "*" or is_valid_did(aud)):
        return None
    return {"kind": "rpc", "lxm": lxm, "aud": aud}


def parse_scope_token(token: str) -> dict | None:
    if token == "atproto":
        return {"kind": "atproto"}
    if token == "transition:generic":
        return {"kind": "transition"}
    if token.startswith("repo:"):
        collection = token[len("repo:"):]
        return {"kind": "repo", "collection": collection} if is_valid_nsid(collection) else None
    if token.startswith("blob:"):
        mime = token[len("blob:"):]
        return {"kind": "blob", "mime": mime} if mime == "*/*" else None
    if token.startswith("rpc:"):
        return _parse_rpc(token)
    return parse_space_scope(token)


def parse_scope(scope: str) -> list[dict] | None:
    raw = [token for token in re.split(r"\s+", scope) if token]
    if not raw or "atproto" not in raw:
        return None
    tokens = []
    for token in raw:
        parsed = parse_scope_token(token)
        if parsed is None:
            return None
        tokens.append(parsed)
    return tokens


def is_valid_scope_string(scope: str) -> bool:
    return parse_scope(scope) is not None


def enforce_scope(scope: str, op: str, collections: list[str]) -> str | None:
    """None when `scope` permits op ("write" | "uploadBlob"); else the missing scope."""
    tokens = parse_scope(scope)
    if tokens is None:
        return "scope"
    has_transition = any(token["kind"] == "transition" for token in tokens)
    repo_nsids = {token["collection"] for token in tokens if token["kind"] == "repo"}
    has_blob = any(token["kind"] == "blob" and token["mime"] == "*/*" for token in tokens)
    if op == "uploadBlob":
        return None if has_transition or has_blob else "blob"
    for collection in collections:
        if not has_transition and collection not in repo_nsids:
            return collection
    return None


def enforce_rpc_scope(scope: str, lxm: str, aud: str) -> str | None:
    tokens = parse_scope(scope)
    if tokens is None:
        return "scope"
    permitted = any(
        token["kind"] == "rpc" and token["lxm"] in ("*", lxm) and token["aud"] in ("*", aud)
        for token in tokens
    )
    return None if permitted else f"{lxm}?aud={aud}"
