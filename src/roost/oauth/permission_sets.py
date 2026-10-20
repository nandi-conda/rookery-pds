# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""`include:<nsid>?aud=<did#svc>` scopes: resolving atproto permission sets
(https://atproto.com/specs/permission#permission-sets) and expanding them into
the concrete repo: and rpc: scopes roost enforces.

A set is a lexicon schema published as a com.atproto.lexicon.schema record in
the repo named by `_lexicon.<authority>` DNS TXT. Resolved sets are cached in D1:
fresh for 24 hours, then re-resolved, falling back to the stale copy if that
fails. The record is fetched over HTTPS from the authority's PDS without
verifying its commit signature."""

import json
import time
from urllib.parse import quote

from ..spaces.identity import IdentityError, doc_service_endpoint, resolve_did_doc
from ..spaces.scopes import parse_space_scope
from ..syntax import is_valid_did, is_valid_nsid
from .scopes import REPO_ACTIONS, parse_scope

DOH_URL = "https://cloudflare-dns.com/dns-query"
STALE_S = 24 * 3600

SCHEMA = """
CREATE TABLE IF NOT EXISTS oauth_permission_sets (
  nsid TEXT PRIMARY KEY,
  main TEXT NOT NULL,
  fetched_at INTEGER NOT NULL
);
"""

_initialized = False


class PermissionSetError(Exception):
    pass


async def init_permission_sets(db) -> None:
    global _initialized
    if not _initialized:
        await db.run(SCHEMA)
        _initialized = True


def authority_domain(nsid: str) -> str:
    """social.colibri.permissionAccount -> colibri.social"""
    return ".".join(reversed(nsid.split(".")[:-1]))


async def _lexicon_did(env, nsid: str) -> str:
    name = f"_lexicon.{authority_domain(nsid)}"
    try:
        response = await env.http.fetch(
            f"{DOH_URL}?name={quote(name)}&type=TXT", headers={"accept": "application/dns-json"}, timeout=5,
        )
        answers = response.json().get("Answer") or [] if response.ok else []
    except Exception as exc:
        raise PermissionSetError(f"could not look up {name}: {exc}") from exc
    for answer in answers:
        value = str(answer.get("data", "")).strip('"')
        if answer.get("type") == 16 and value.startswith("did="):
            did = value[len("did="):]
            if is_valid_did(did):
                return did
    raise PermissionSetError(f"no lexicon authority DID at {name}")


async def _fetch_main(env, nsid: str) -> dict:
    did = await _lexicon_did(env, nsid)
    try:
        doc = await resolve_did_doc(env, did)
    except IdentityError as exc:
        raise PermissionSetError(str(exc)) from exc
    pds = doc_service_endpoint(doc, "atproto_pds")
    if not pds:
        raise PermissionSetError(f"{did} has no PDS")
    url = (f"{pds.rstrip('/')}/xrpc/com.atproto.repo.getRecord?repo={quote(did)}"
           f"&collection=com.atproto.lexicon.schema&rkey={quote(nsid)}")
    try:
        response = await env.http.fetch(url, timeout=5)
        record = response.json() if response.ok else None
    except Exception as exc:
        raise PermissionSetError(f"could not fetch lexicon {nsid}: {exc}") from exc
    value = record.get("value") if isinstance(record, dict) else None
    main = (value.get("defs") or {}).get("main") if isinstance(value, dict) and value.get("id") == nsid else None
    if not isinstance(main, dict) or main.get("type") != "permission-set" or not isinstance(main.get("permissions"), list):
        raise PermissionSetError(f"{nsid} is not a permission set")
    return main


async def resolve_permission_set(env, nsid: str, now: int | None = None) -> dict:
    """The set's `main` definition, from the D1 cache or the network."""
    now = int(time.time()) if now is None else now
    await init_permission_sets(env.db)
    row = await env.db.first("SELECT main, fetched_at FROM oauth_permission_sets WHERE nsid = ?", nsid)
    if row and now - row["fetched_at"] < STALE_S:
        return json.loads(row["main"])
    try:
        main = await _fetch_main(env, nsid)
    except PermissionSetError:
        if row:
            return json.loads(row["main"])
        raise
    await env.db.run(
        """INSERT INTO oauth_permission_sets (nsid, main, fetched_at) VALUES (?, ?, ?)
           ON CONFLICT (nsid) DO UPDATE SET main = excluded.main, fetched_at = excluded.fetched_at""",
        nsid, json.dumps(main, separators=(",", ":")), now,
    )
    return main


def _in_namespace(set_nsid: str, nsid) -> bool:
    group = set_nsid.rsplit(".", 1)[0]
    return isinstance(nsid, str) and is_valid_nsid(nsid) and nsid.startswith(group + ".")


def _string_list(value) -> list | None:
    return value if isinstance(value, list) and value and all(isinstance(item, str) for item in value) else None


SPACE_KEYS = {"type", "resource", "spaceType", "authority", "skey", "collection", "action", "manage"}


def _space_token(set_nsid: str, permission: dict) -> str | None:
    """A space: scope (spaces.scopes syntax) for a space permission whose space type
    and collections are in the set's namespace; None to ignore it."""
    if set(permission) - SPACE_KEYS or not _in_namespace(set_nsid, permission.get("spaceType")):
        return None
    params = [("authority", permission.get("authority", "self")), ("skey", permission.get("skey", "*"))]
    for key in ("collection", "action", "manage"):
        if key in permission:
            values = _string_list(permission[key])
            if values is None or (key == "collection" and not all(_in_namespace(set_nsid, c) for c in values)):
                return None
            params += [(key, value) for value in values]
    if not all(isinstance(value, str) for _, value in params):
        return None
    token = f"space:{permission['spaceType']}?" + "&".join(f"{key}={quote(value, safe=':*')}" for key, value in params)
    return token if parse_space_scope(token) else None


def expand_permission_set(set_nsid: str, main: dict, aud: str | None) -> list[str]:
    """Concrete scope tokens for one include. Permissions roost can't express exactly,
    or that the spec says to ignore, grant nothing."""
    tokens = []
    for permission in main.get("permissions", []):
        if not isinstance(permission, dict) or permission.get("type") != "permission":
            continue
        resource = permission.get("resource")
        if resource == "repo":
            if set(permission) - {"type", "resource", "collection", "action"}:
                continue
            collections = _string_list(permission.get("collection"))
            actions = permission.get("action")
            if not collections or (actions is not None and not (_string_list(actions) and set(actions) <= REPO_ACTIONS)):
                continue
            partial = actions is not None and set(actions) != REPO_ACTIONS
            query = "?" + "&".join(f"action={action}" for action in sorted(set(actions))) if partial else ""
            tokens += [f"repo:{c}{query}" for c in collections if _in_namespace(set_nsid, c)]
        elif resource == "space":
            token = _space_token(set_nsid, permission)
            if token:
                tokens.append(token)
        elif resource == "rpc":
            if set(permission) - {"type", "resource", "lxm", "aud", "inheritAud"}:
                continue
            lxms = _string_list(permission.get("lxm"))
            inherit = permission.get("inheritAud") is True
            if inherit:
                if "aud" in permission or not aud:
                    continue
                target = aud
            elif permission.get("aud") == "*":
                target = "*"
            else:
                continue
            if lxms:
                tokens += [f"rpc:{lxm}?aud={quote(target, safe=':*')}" for lxm in lxms if _in_namespace(set_nsid, lxm)]
    return tokens


async def effective_scope(env, scope: str, now: int | None = None) -> str:
    """`scope` with each include: token's expansion appended (the include tokens stay,
    and enforcement ignores them)."""
    if "include:" not in scope:
        return scope
    tokens = parse_scope(scope)
    if tokens is None:
        return scope
    extra = []
    for token in tokens:
        if token["kind"] == "include":
            main = await resolve_permission_set(env, token["nsid"], now)
            extra += expand_permission_set(token["nsid"], main, token["aud"])
    return " ".join([scope, *dict.fromkeys(extra)])
