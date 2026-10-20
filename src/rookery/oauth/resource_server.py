# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Resolving an OAuth access token (rkat_...) presented with its DPoP proof."""

from .. import directory
from ..encoding import sha256_b64url
from .dpop import DpopError, validate_oauth_dpop_proof
from .store import get_token_with_session, init_oauth


class InvalidOauthTokenError(Exception):
    def __init__(self):
        super().__init__("Invalid OAuth access token")


async def resolve_oauth_access_token(access_token: str, dpop_jwt: str, method: str, url: str, env, now: int) -> dict:
    """{did, do_id, scope} for a live token bound to this proof's key."""
    db = env.db
    await init_oauth(db)
    await directory.init_directory(db)
    try:
        proof = await validate_oauth_dpop_proof(
            dpop_jwt, method, url, access_token,
            db=db, nonce_secret=env.OAUTH_NONCE_SECRET or "", now=now, require_nonce=False,
        )
    except DpopError as exc:
        raise InvalidOauthTokenError() from exc
    row = await get_token_with_session(db, sha256_b64url(access_token))
    if not row or row["exp"] <= now or row["session_exp"] <= now or row["dpop_jkt"] != proof["thumbprint"]:
        raise InvalidOauthTokenError()
    try:
        resolved = await directory.resolve_repo(db, row["did"])
    except directory.RepoNotFoundError as exc:
        raise InvalidOauthTokenError() from exc
    return {"did": row["did"], "do_id": resolved["do_id"], "scope": row["scope"]}
