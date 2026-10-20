# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The simplespace implementation's policies, as simplespace/ in the reference PDS:
who may read or write a space (public, member list, or the managing app's call)
and which apps may (open, or an allow-list of attested client_ids)."""

import json
import logging
import time
from urllib.parse import urlencode

from ..errors import XrpcError
from .identity import service_endpoint
from .refs import SpaceRef

log = logging.getLogger("roost.spaces")

DEFS = "com.atproto.simplespace.defs"
CHECK_USER_ACCESS = "com.atproto.simplespace.checkUserAccess"


def policy_to_db(policy) -> tuple[str, str | None]:
    kind = policy.get("$type") if isinstance(policy, dict) else None
    if kind == f"{DEFS}#publicPolicy":
        return "public", None
    if kind == f"{DEFS}#memberListPolicy":
        return "member-list", None
    if kind == f"{DEFS}#managingAppPolicy":
        managing_app = policy.get("managingApp")
        if not isinstance(managing_app, str) or not managing_app.startswith("did:"):
            raise XrpcError("UnsupportedPolicy",
                            f"managingApp must be a DID with an optional service fragment, got: {managing_app}")
        return "managing-app", managing_app
    raise XrpcError("UnsupportedPolicy", f"Unsupported policy: {kind}")


def app_access_to_db(app_access) -> tuple[str, str]:
    kind = app_access.get("$type") if isinstance(app_access, dict) else None
    if kind == f"{DEFS}#open":
        return "open", "[]"
    if kind == f"{DEFS}#allowList":
        allowed = app_access.get("allowed")
        if not isinstance(allowed, list) or not all(isinstance(item, str) for item in allowed):
            raise XrpcError("UnsupportedAppAccess", "allowList.allowed must be a list of client IDs")
        return "allowList", json.dumps(allowed)
    raise XrpcError("UnsupportedAppAccess", f"Unsupported appAccess: {kind}")


def config_from_input(body: dict, partial: bool = False) -> dict:
    config = {}
    for field in ("readPolicy", "writePolicy"):
        if field in body or not partial:
            prefix = "read" if field == "readPolicy" else "write"
            config[f"{prefix}_policy"], config[f"{prefix}_managing_app"] = policy_to_db(body.get(field))
    if "appAccess" in body or not partial:
        config["app_access_type"], config["app_allowed"] = app_access_to_db(body.get("appAccess"))
    return config


def _policy_to_lex(policy: str, managing_app: str | None) -> dict:
    if policy == "public":
        return {"$type": f"{DEFS}#publicPolicy"}
    if policy == "managing-app":
        return {"$type": f"{DEFS}#managingAppPolicy", "managingApp": managing_app or ""}
    return {"$type": f"{DEFS}#memberListPolicy"}


def config_to_lex(config: dict) -> dict:
    if config["app_access_type"] == "allowList":
        app_access = {"$type": f"{DEFS}#allowList", "allowed": json.loads(config["app_allowed"])}
    else:
        app_access = {"$type": f"{DEFS}#open"}
    return {
        "uri": config["uri"],
        "readPolicy": _policy_to_lex(config["read_policy"], config["read_managing_app"]),
        "writePolicy": _policy_to_lex(config["write_policy"], config["write_managing_app"]),
        "appAccess": app_access,
    }


async def authorize_user(env, authority, config: dict, user_did: str, access: str,
                         client_id: str | None = None) -> bool:
    """`authority` is the space authority's AccountClient."""
    space = SpaceRef.parse(config["uri"])
    if user_did == space.did:
        return True  # the authority can never lock itself out
    policy = config[f"{access}_policy"]
    if policy == "public":
        return True
    if policy == "member-list":
        member = await authority.space_get_member(space=config["uri"], did=user_did)
        return bool(member and member[access])
    if policy == "managing-app":
        return await _check_managing_app(env, authority, config, user_did, access, client_id)
    return False


async def _check_managing_app(env, authority, config, user_did, access, client_id) -> bool:
    managing_app = config[f"{access}_managing_app"]
    if not managing_app:
        return False
    try:
        endpoint = await service_endpoint(env, managing_app)
        if not endpoint:
            log.warning("could not resolve managing app %s", managing_app)
            return False
        token = await authority.sign_service_auth(aud=managing_app, lxm=CHECK_USER_ACCESS, exp=int(time.time()) + 60)
        params = {"space": config["uri"], "user": user_did, "access": access}
        if client_id:
            params["clientId"] = client_id
        response = await env.http.fetch(
            f"{endpoint}/xrpc/{CHECK_USER_ACCESS}?{urlencode(params)}",
            headers={"Authorization": f"Bearer {token['token']}"}, timeout=10,
        )
        return response.ok and response.json().get("authorized") is True
    except Exception as exc:
        # An unreachable managing app denies: failing open would hand out access to
        # the spaces that asked for the strictest gate.
        log.warning("managing app check failed for %s: %s", config["uri"], exc)
        return False


async def authorize_credential(env, authority, config: dict, user_did: str, client_id: str | None) -> None:
    """The app perimeter first (decided from config alone), then the user's read access."""
    if config["app_access_type"] == "allowList":
        if not client_id or client_id not in json.loads(config["app_allowed"]):
            raise XrpcError("AppNotAuthorized", "Application not authorized for this space")
    if not await authorize_user(env, authority, config, user_did, "read", client_id):
        raise XrpcError("UserNotAuthorized", "User not authorized for this space")
