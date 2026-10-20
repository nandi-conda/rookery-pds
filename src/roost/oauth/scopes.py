# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The OAuth scopes roost grants: atproto, transition:generic, repo:<nsid>[?action=...],
blob:*/*, rpc:<lxm>?aud=<did[#service]|*>, include:<nsid>?aud=<did#service>
(expanded by oauth.permission_sets), and space:<type>?... (see spaces.scopes)."""

import re
from urllib.parse import parse_qsl

from ..spaces.scopes import parse_space_scope
from ..syntax import is_valid_did, is_valid_nsid


def is_valid_aud(value) -> bool:
    """A DID, optionally with a #service fragment."""
    if not isinstance(value, str):
        return False
    did, sep, fragment = value.partition("#")
    return is_valid_did(did) and (not sep or bool(fragment))


def aud_matches(granted: str, aud: str) -> bool:
    """A granted aud without a fragment covers every service of that DID."""
    return granted in ("*", aud) or ("#" not in granted and granted == aud.partition("#")[0])


REPO_ACTIONS = frozenset({"create", "update", "delete"})


def _parse_repo(token: str) -> dict | None:
    """repo:<nsid>[?action=create&action=update&action=delete]; no action means all."""
    collection, _, query = token[len("repo:"):].partition("?")
    if not is_valid_nsid(collection):
        return None
    params = parse_qsl(query, keep_blank_values=True)
    if any(key != "action" or value not in REPO_ACTIONS for key, value in params):
        return None
    actions = frozenset(value for _, value in params) or REPO_ACTIONS
    return {"kind": "repo", "collection": collection, "actions": actions}


def _parse_include(token: str) -> dict | None:
    nsid, _, query = token[len("include:"):].partition("?")
    if not is_valid_nsid(nsid):
        return None
    params = parse_qsl(query, keep_blank_values=True)
    if any(key != "aud" for key, _ in params) or len(params) > 1:
        return None
    aud = params[0][1] if params else None
    if aud is not None and not (is_valid_aud(aud) and "#" in aud):
        return None
    return {"kind": "include", "nsid": nsid, "aud": aud}


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
    if not aud or not (aud == "*" or is_valid_aud(aud)):
        return None
    return {"kind": "rpc", "lxm": lxm, "aud": aud}


def parse_scope_token(token: str) -> dict | None:
    if token == "atproto":
        return {"kind": "atproto"}
    if token == "transition:generic":
        return {"kind": "transition"}
    if token.startswith("repo:"):
        return _parse_repo(token)
    if token.startswith("blob:"):
        mime = token[len("blob:"):]
        return {"kind": "blob", "mime": mime} if mime == "*/*" else None
    if token.startswith("rpc:"):
        return _parse_rpc(token)
    if token.startswith("include:"):
        return _parse_include(token)
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


def enforce_scope(scope: str, op: str, writes: list[tuple[str, str]]) -> str | None:
    """None when `scope` permits op ("write" | "uploadBlob"); else the missing scope.
    `writes` are (collection, action) pairs, action being create, update or delete."""
    tokens = parse_scope(scope)
    if tokens is None:
        return "scope"
    has_transition = any(token["kind"] == "transition" for token in tokens)
    has_blob = any(token["kind"] == "blob" and token["mime"] == "*/*" for token in tokens)
    if op == "uploadBlob":
        return None if has_transition or has_blob else "blob"
    if has_transition:
        return None
    granted = {(token["collection"], action) for token in tokens if token["kind"] == "repo" for action in token["actions"]}
    for collection, action in writes:
        if (collection, action) not in granted:
            return f"repo:{collection}?action={action}"
    return None


def enforce_rpc_scope(scope: str, lxm: str, aud: str) -> str | None:
    """transition:generic covers every service call but chat.bsky.*, as in @atproto/oauth-scopes."""
    tokens = parse_scope(scope)
    if tokens is None:
        return "scope"
    has_transition = any(token["kind"] == "transition" for token in tokens)
    permitted = (has_transition and not lxm.startswith("chat.bsky.")) or any(
        token["kind"] == "rpc" and token["lxm"] in ("*", lxm) and aud_matches(token["aud"], aud)
        for token in tokens
    )
    return None if permitted else f"{lxm}?aud={aud}"
