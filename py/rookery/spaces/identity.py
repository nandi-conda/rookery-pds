# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Resolving other parties' DIDs: their atproto signing keys (for space tokens,
commits and service auth) and their service endpoints (for notifications)."""

import time
from urllib.parse import quote

from .. import directory
from ..syntax import is_valid_did

CACHE_TTL_S = 300
_cache: dict[str, tuple[dict, float]] = {}


class IdentityError(Exception):
    pass


async def resolve_did_doc(env, did: str, force_refresh: bool = False) -> dict:
    if not is_valid_did(did):
        raise IdentityError(f"invalid DID: {did}")
    cached = _cache.get(did)
    if cached and not force_refresh and time.time() - cached[1] < CACHE_TTL_S:
        return cached[0]
    if did.startswith("did:plc:"):
        url = f"{env.ROOKERY_PLC_URL}/{quote(did)}"
    elif did.startswith("did:web:"):
        host = did[len("did:web:"):]
        if ":" in host:
            raise IdentityError(f"unsupported did:web (path form): {did}")
        host = host.replace("%3A", ":")
        url = f"https://{host}/.well-known/did.json"
    else:
        raise IdentityError(f"unsupported DID method: {did}")
    try:
        response = await env.http.fetch(url, timeout=5)
    except Exception as exc:
        raise IdentityError(f"could not resolve {did}: {exc}") from exc
    if not response.ok:
        raise IdentityError(f"could not resolve {did} ({response.status})")
    try:
        doc = response.json()
    except ValueError as exc:
        raise IdentityError(f"could not resolve {did}: invalid DID document") from exc
    if not isinstance(doc, dict) or doc.get("id") != did:
        raise IdentityError(f"could not resolve {did}: DID document id mismatch")
    _cache[did] = (doc, time.time())
    return doc


def _matches(entry_id, did: str, fragment: str) -> bool:
    return entry_id in (f"#{fragment}", f"{did}#{fragment}")


def doc_signing_key(doc: dict, key_id: str = "atproto") -> str | None:
    for method in doc.get("verificationMethod") or []:
        if isinstance(method, dict) and _matches(method.get("id"), doc["id"], key_id):
            multibase = method.get("publicKeyMultibase")
            if isinstance(multibase, str) and multibase.startswith("z"):
                return f"did:key:{multibase}"
    return None


def doc_service_endpoint(doc: dict, fragment: str) -> str | None:
    for service in doc.get("service") or []:
        if isinstance(service, dict) and _matches(service.get("id"), doc["id"], fragment):
            endpoint = service.get("serviceEndpoint")
            if isinstance(endpoint, str) and endpoint.startswith(("https://", "http://localhost")):
                return endpoint.rstrip("/")
    return None


async def local_account(env, did: str) -> dict | None:
    """{did, handle, do_id} when the DID is hosted here."""
    await directory.init_directory(env.db)
    try:
        return await directory.resolve_repo(env.db, did)
    except directory.RepoNotFoundError:
        return None


async def signing_key(env, did: str, key_id: str = "atproto", force_refresh: bool = False) -> str:
    """The did:key an issuer signs with; an account hosted here is answered by its DO."""
    if key_id == "atproto":
        local = await local_account(env, did)
        if local:
            return await env.account(local["do_id"]).space_signing_key()
    key = doc_signing_key(await resolve_did_doc(env, did, force_refresh), key_id)
    if not key:
        raise IdentityError(f"missing or bad key (#{key_id}) in did doc: {did}")
    return key


async def service_endpoint(env, service: str) -> str | None:
    """Resolve a service identifier (a DID with an optional #fragment) to its endpoint.
    A bare DID names an account, served by its #atproto_pds; #atproto_space_host
    falls back to #atproto_pds when the DID publishes no dedicated entry."""
    did, _, fragment = service.partition("#")
    try:
        doc = await resolve_did_doc(env, did)
    except IdentityError:
        return None
    if fragment == "atproto_space_host":
        return doc_service_endpoint(doc, "atproto_space_host") or doc_service_endpoint(doc, "atproto_pds")
    return doc_service_endpoint(doc, fragment or "atproto_pds")
