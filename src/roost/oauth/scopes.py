# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The OAuth scopes roost grants: atproto, transition:generic, repo:<nsid>[?action=...] (or repo?collection=...),
blob:<mime pattern>, rpc:<lxm>?aud=<did[#service]|*>, include:<nsid>?aud=<did#service>
(expanded by oauth.permission_sets), and space:<type>?... (see spaces.scopes)."""

import re
from urllib.parse import parse_qsl, unquote

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


def _positional(token: str, prefix: str) -> tuple[list[str], str] | None:
    """Split `prefix:<value>?<query>` or `prefix?<query>` into its positional values and query."""
    body = token[len(prefix):]
    if body.startswith(":"):
        value, _, query = body[1:].partition("?")
        return [unquote(value)], query
    if body.startswith("?"):
        return [], body[1:]
    return None


def _parse_repo(token: str) -> dict | None:
    """repo:<nsid>[?action=...] or repo?collection=<nsid>&collection=...[&action=...]; no action means all."""
    split = _positional(token, "repo")
    if split is None:
        return None
    collections, query = split
    params = parse_qsl(query, keep_blank_values=True)
    if any(key not in ("collection", "action") or (key == "action" and value not in REPO_ACTIONS)
           for key, value in params):
        return None
    collections += [value for key, value in params if key == "collection"]
    if not collections or not all(is_valid_nsid(collection) for collection in collections):
        return None
    actions = frozenset(value for key, value in params if key == "action") or REPO_ACTIONS
    return {"kind": "repo", "collections": frozenset(collections), "actions": actions}


_MIME_PART = r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*"
_MIME_PATTERN = re.compile(rf"\*/\*|{_MIME_PART}/(\*|{_MIME_PART})")


def _parse_blob(token: str) -> dict | None:
    """blob:<accept> or blob?accept=<accept>[&accept=...]; each accept is */*, type/* or type/subtype."""
    split = _positional(token, "blob")
    if split is None:
        return None
    accepts, query = split
    params = parse_qsl(query, keep_blank_values=True)
    if any(key != "accept" for key, _ in params):
        return None
    accepts += [value for _, value in params]
    if not accepts or not all(_MIME_PATTERN.fullmatch(accept) for accept in accepts):
        return None
    return {"kind": "blob", "accept": frozenset(accepts)}


def mime_accepted(accept, mime_type: str) -> bool:
    mime = mime_type.split(";")[0].strip().lower()
    return any(
        pattern == "*/*" or pattern.lower() == mime
        or (pattern.endswith("/*") and mime.startswith(pattern[:-1].lower()))
        for pattern in accept
    )


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
    """rpc:<lxm>?aud=<aud> or rpc?lxm=<lxm>&lxm=...&aud=<aud>."""
    split = _positional(token, "rpc")
    if split is None:
        return None
    lxms, query = split
    params = parse_qsl(query, keep_blank_values=True)
    if any(key not in ("lxm", "aud") for key, _ in params):
        return None
    lxms += [value for key, value in params if key == "lxm"]
    if not lxms or not all(lxm == "*" or is_valid_nsid(lxm) for lxm in lxms):
        return None
    auds = [value for key, value in params if key == "aud"]
    if len(auds) != 1 or not (auds[0] == "*" or is_valid_aud(auds[0])):
        return None
    return {"kind": "rpc", "lxms": frozenset(lxms), "aud": auds[0]}


def parse_scope_token(token: str) -> dict | None:
    if token == "atproto":
        return {"kind": "atproto"}
    if token == "transition:generic":
        return {"kind": "transition"}
    if token.startswith(("repo:", "repo?")):
        return _parse_repo(token)
    if token.startswith(("blob:", "blob?")):
        return _parse_blob(token)
    if token.startswith(("rpc:", "rpc?")):
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


def enforce_scope(scope: str, op: str, writes: list[tuple[str, str]], mime_type: str = "") -> str | None:
    """None when `scope` permits op ("write" | "uploadBlob" of `mime_type`); else the missing scope.
    `writes` are (collection, action) pairs, action being create, update or delete."""
    tokens = parse_scope(scope)
    if tokens is None:
        return "scope"
    has_transition = any(token["kind"] == "transition" for token in tokens)
    if op == "uploadBlob":
        has_blob = any(token["kind"] == "blob" and mime_accepted(token["accept"], mime_type) for token in tokens)
        return None if has_transition or has_blob else f"blob:{mime_type}"
    if has_transition:
        return None
    granted = {(collection, action) for token in tokens if token["kind"] == "repo"
               for collection in token["collections"] for action in token["actions"]}
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
        token["kind"] == "rpc" and ("*" in token["lxms"] or lxm in token["lxms"]) and aud_matches(token["aud"], aud)
        for token in tokens
    )
    return None if permitted else f"{lxm}?aud={aud}"
