# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""What a Bluesky client expects from its PDS beyond the repo: stored
preferences, and XRPC calls the PDS doesn't serve forwarded to an app view (or
the service an `atproto-proxy` header names) with service auth for the caller.

Registered last, so `/xrpc/:nsid` only catches methods no other route serves.
"""

import json
import time

from ..app import authenticate, read_json, router
from ..errors import XrpcError
from ..oauth.scopes import enforce_rpc_scope
from ..spaces.identity import service_endpoint
from ..syntax import is_valid_did, is_valid_nsid
from ..web import Response, json_response
from . import store

DEFAULT_SERVICES = {
    "app.bsky.": ("did:web:api.bsky.app#bsky_appview", "https://api.bsky.app"),
    "chat.bsky.": ("did:web:api.bsky.chat#bsky_chat", "https://api.bsky.chat"),
}
FORWARD_REQUEST_HEADERS = ("content-type", "accept", "accept-language", "atproto-accept-labelers")
FORWARD_RESPONSE_HEADERS = ("content-type", "atproto-content-labelers", "atproto-repo-rev")


@router.get("/xrpc/app.bsky.actor.getPreferences")
async def get_preferences(request, env):
    auth = await authenticate(request, env, "GET")
    await store.init_humans(env.db)
    row = await env.db.first("SELECT preferences FROM actor_preferences WHERE did = ?", auth["did"])
    return json_response({"preferences": json.loads(row["preferences"]) if row else []})


@router.post("/xrpc/app.bsky.actor.putPreferences")
async def put_preferences(request, env):
    auth = await authenticate(request, env, "POST")
    body = await read_json(request)
    preferences = body.get("preferences") if body else None
    if not isinstance(preferences, list) or not all(isinstance(item, dict) and "$type" in item for item in preferences):
        raise XrpcError("InvalidRequest", "preferences must be a list of typed objects")
    encoded = json.dumps(preferences, separators=(",", ":"))
    if len(encoded) > 100_000:
        raise XrpcError("InvalidRequest", "preferences are too large")
    await store.init_humans(env.db)
    await env.db.run(
        """INSERT INTO actor_preferences (did, preferences) VALUES (?, ?)
           ON CONFLICT (did) DO UPDATE SET preferences = excluded.preferences""",
        auth["did"], encoded,
    )
    return Response(200, b"", [])


async def proxy_target(request, nsid: str) -> tuple[str, str] | None:
    """(service DID for aud, endpoint) for a call, or None when nothing serves it."""
    header = request.header("atproto-proxy")
    if header:
        did, _, fragment = header.partition("#")
        if not is_valid_did(did) or not fragment:
            raise XrpcError("InvalidRequest", "atproto-proxy must be a DID with a #service fragment")
        return did, header
    for prefix, (service, endpoint) in DEFAULT_SERVICES.items():
        if nsid.startswith(prefix):
            return service.partition("#")[0], endpoint
    return None


async def forward(request, env):
    nsid = request.params["nsid"]
    if not is_valid_nsid(nsid):
        raise XrpcError("InvalidRequest", "Invalid method")
    target = await proxy_target(request, nsid)
    if target is None:
        raise XrpcError("MethodNotImplemented", f"Method not implemented: {nsid}", 501)
    aud, endpoint = target
    if endpoint.startswith("did:"):
        resolved = await service_endpoint(env, endpoint)
        if not resolved:
            raise XrpcError("UpstreamFailure", f"Could not resolve proxy service {endpoint}", 502)
        endpoint = resolved
    headers = {name: request.header(name) for name in FORWARD_REQUEST_HEADERS if request.header(name)}
    if request.header("authorization"):
        auth = await authenticate(request, env, request.method)
        if auth["kind"] == "oauth":
            denied = enforce_rpc_scope(auth["scope"], nsid, aud)
            if denied:
                raise XrpcError("InsufficientScope", f"Scope does not permit {denied}", 403)
        token = await env.account(auth["do_id"]).sign_service_auth(aud=aud, lxm=nsid, exp=int(time.time()) + 60)
        headers["authorization"] = f"Bearer {token['token']}"
    body = await request.bytes() if request.method == "POST" else None
    try:
        upstream = await env.http.fetch(
            f"{endpoint}/xrpc/{nsid}{request.search}", method=request.method, headers=headers, body=body, timeout=30,
        )
    except Exception as exc:
        raise XrpcError("UpstreamFailure", f"Upstream request failed: {exc}", 502) from exc
    response = Response(upstream.status, upstream.body, [])
    for name in FORWARD_RESPONSE_HEADERS:
        value = upstream.headers.get(name)
        if value:
            response.set_header(name, value)
    return response


router.get("/xrpc/:nsid")(forward)
router.post("/xrpc/:nsid")(forward)
