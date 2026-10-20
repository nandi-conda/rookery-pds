# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""OAuth `space:` permissions, as space-permission.ts in @atproto/oauth-scopes:

    space:<type|*>?authority=<did|self|*>&skey=<skey|*>&collection=<nsid|*>&action=<...>&manage=<...>

authority defaults to self (the granting user), skey to *, action to
read/create/update/delete; collection and manage default to none.
"""

import re
from urllib.parse import parse_qsl, unquote

from ..syntax import is_valid_did, is_valid_nsid, is_valid_record_key

ACTIONS = ("read_self", "read", "create", "update", "delete")
DEFAULT_ACTIONS = ("read", "create", "update", "delete")
MANAGE_OPS = ("create", "update", "delete")
KNOWN_PARAMS = {"type", "authority", "skey", "collection", "action", "manage"}


def parse_space_scope(token: str) -> dict | None:
    if not (token == "space" or token.startswith(("space:", "space?"))):
        return None
    rest = token[len("space"):]
    positional, _, query = rest.partition("?")
    params = parse_qsl(query, keep_blank_values=True) if query else []
    if any(key not in KNOWN_PARAMS for key, _ in params):
        return None
    values = {key: [value for name, value in params if name == key] for key in KNOWN_PARAMS}
    if positional:
        if values["type"]:
            return None
        values["type"] = [unquote(positional[1:])]
    for single in ("type", "authority", "skey"):
        if len(values[single]) > 1:
            return None
    space_type = values["type"][0] if values["type"] else None
    authority = values["authority"][0] if values["authority"] else "self"
    skey = values["skey"][0] if values["skey"] else "*"
    if space_type is None or not (space_type == "*" or is_valid_nsid(space_type)):
        return None
    if not (authority in ("*", "self") or is_valid_did(authority)):
        return None
    if not (skey == "*" or is_valid_record_key(skey)):
        return None
    if any(c != "*" and not is_valid_nsid(c) for c in values["collection"]):
        return None
    if any(a not in ACTIONS for a in values["action"]) or any(m not in MANAGE_OPS for m in values["manage"]):
        return None
    return {
        "kind": "space", "type": space_type, "authority": authority, "skey": skey,
        "collection": values["collection"] or None,
        "action": tuple(values["action"]) or DEFAULT_ACTIONS,
        "manage": tuple(values["manage"]) or None,
    }


def _matches(perm: dict, user_did: str, ref, action: str | None, collection: str | None, manage: str | None) -> bool:
    authority = user_did if perm["authority"] == "self" else perm["authority"]
    if perm["type"] != "*" and perm["type"] != ref["type"]:
        return False
    if authority != "*" and authority != ref["authority"]:
        return False
    if perm["skey"] != "*" and perm["skey"] != ref["skey"]:
        return False
    if action is None:
        return perm["manage"] is not None and manage in perm["manage"]
    if action == "read":
        return "read" in perm["action"]
    if action == "read_self":
        return "read" in perm["action"] or "read_self" in perm["action"]
    collections = perm["collection"] or []
    return action in perm["action"] and ("*" in collections or collection in collections)


def space_scope_denial(scope: str, user_did: str, ref: dict, action: str | None = None,
                       collection: str | None = None, manage: str | None = None) -> str | None:
    """None when an OAuth scope grants the operation; else the scope it would need.
    `ref` is {type, authority, skey}, any of which may be "*" for a listing."""
    perms = [p for p in (parse_space_scope(t) for t in re.split(r"\s+", scope or "") if t) if p]
    if any(_matches(p, user_did, ref, action, collection, manage) for p in perms):
        return None
    needed = f"space:{ref['type']}?authority={ref['authority']}&skey={ref['skey']}"
    if manage:
        return f"{needed}&action=read_self&manage={manage}"
    if action in ("create", "update", "delete"):
        needed += f"&collection={collection}"
    return f"{needed}&action={action}"
