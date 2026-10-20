# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Cloudflare Access JWTs for the commons admin routes."""

import time

from .jwt import JwtFormatError, is_number, parse_jwt, rs256_verify, rsa_public_key

JWKS_TTL_S = 10 * 60


class AccessJwtError(Exception):
    pass


_jwks_cache: dict | None = None


def reset_jwks_cache() -> None:
    global _jwks_cache
    _jwks_cache = None


def _is_access_jwk(value) -> bool:
    return (
        isinstance(value, dict) and isinstance(value.get("kid"), str) and value.get("kty") == "RSA"
        and isinstance(value.get("n"), str) and isinstance(value.get("e"), str)
    )


async def _fetch_keys(env) -> dict:
    global _jwks_cache
    if not env.CF_ACCESS_TEAM_DOMAIN:
        raise AccessJwtError("Access team domain is not configured")
    response = await env.http.fetch(f"https://{env.CF_ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs")
    if not response.ok:
        raise AccessJwtError("Access JWKS fetch failed")
    try:
        body = response.json()
    except ValueError as exc:
        raise AccessJwtError("Access JWKS response is invalid JSON") from exc
    keys = body.get("keys") if isinstance(body, dict) else None
    if not isinstance(keys, list):
        raise AccessJwtError("Access JWKS response missing keys")
    imported = {}
    for key in keys:
        if not _is_access_jwk(key):
            raise AccessJwtError("Access JWKS contains an invalid key")
        try:
            imported[key["kid"]] = rsa_public_key(key["n"], key["e"])
        except (ValueError, TypeError) as exc:
            raise AccessJwtError("invalid Access public key") from exc
    if not imported:
        raise AccessJwtError("Access JWKS contains no keys")
    _jwks_cache = {"keys": imported, "fetched_at": time.time()}
    return _jwks_cache


async def _get_keys(env) -> dict:
    if _jwks_cache and time.time() - _jwks_cache["fetched_at"] < JWKS_TTL_S:
        return _jwks_cache
    return await _fetch_keys(env)


def _assert_claims(payload: dict, env) -> dict:
    if not env.CF_ACCESS_TEAM_DOMAIN or not env.CF_ACCESS_AUD:
        raise AccessJwtError("Access is not configured")
    if payload.get("iss") != f"https://{env.CF_ACCESS_TEAM_DOMAIN}":
        raise AccessJwtError("Access JWT issuer mismatch")
    aud = payload.get("aud")
    audiences = [aud] if isinstance(aud, str) else aud
    if (
        not isinstance(audiences, list) or not all(isinstance(item, str) for item in audiences)
        or env.CF_ACCESS_AUD not in audiences
    ):
        raise AccessJwtError("Access JWT audience mismatch")
    if not is_number(payload.get("exp")):
        raise AccessJwtError("Access JWT missing exp")
    if not is_number(payload.get("iat")):
        raise AccessJwtError("Access JWT missing iat")
    now = int(time.time())
    if payload["exp"] <= now:
        raise AccessJwtError("Access JWT expired")
    if payload["iat"] > now + 60:
        raise AccessJwtError("Access JWT iat is in the future")
    return payload


async def verify_access_jwt(token: str, env) -> dict:
    try:
        header, payload, signing_input, signature = parse_jwt(token)
    except JwtFormatError as exc:
        raise AccessJwtError("Access JWT is malformed") from exc
    if header.get("alg") != "RS256":
        raise AccessJwtError("Access JWT alg must be RS256")
    if not isinstance(header.get("kid"), str):
        raise AccessJwtError("Access JWT missing kid")
    cache = await _get_keys(env)
    key = cache["keys"].get(header["kid"])
    if key is None:
        key = (await _fetch_keys(env))["keys"].get(header["kid"])
    if key is None:
        raise AccessJwtError("Access JWT kid is unknown")
    if not rs256_verify(key, signature, signing_input):
        raise AccessJwtError("Access JWT signature verification failed")
    return _assert_claims(payload, env)
