# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""OAuth client metadata: the built-in rook CLI client, atproto loopback
clients, and fetched client_id metadata documents; plus client authentication
(none or private_key_jwt)."""

import json
import re
import time

from ..encoding import sha256_b64url
from ..jwt import JwtFormatError, is_number, parse_jwt
from ..urls import parse_url
from .dpop import DpopError, _verify_es256
from .store import insert_dpop_jti

CACHE_TTL_S = 10 * 60
DEFAULT_TIMEOUT_S = 10
MAX_CLIENT_METADATA_BYTES = 64 * 1024
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class ClientMetadataError(ValueError):
    pass


class ClientAuthError(ValueError):
    pass


def rook_cli_client_metadata(hostname: str) -> dict:
    origin = f"https://{hostname}"
    return {
        "client_id": f"{origin}/client-metadata.json",
        "client_name": "rook cli",
        "application_type": "native",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "redirect_uris": ["http://127.0.0.1/callback"],
        # Knot RPC scopes still name the commons knot; login works without knot membership.
        "scope": "atproto",
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": True,
        "client_uri": origin,
    }


# The commons (rook.host) built-in id.
ROOK_CLI_CLIENT_METADATA = rook_cli_client_metadata("rook.host")

_cache: dict[str, tuple[dict, float]] = {}


def reset_cache() -> None:
    _cache.clear()


def _scopes(scope: str) -> list[str]:
    return [token for token in re.split(r"\s+", scope) if token]


def _is_string_list(value) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_ec_public_jwk(value) -> bool:
    return (
        isinstance(value, dict) and value.get("kty") == "EC" and value.get("crv") == "P-256"
        and isinstance(value.get("x"), str) and isinstance(value.get("y"), str) and "d" not in value
    )


def _is_loopback_client_id(url) -> bool:
    return url.protocol == "http:" and url.hostname == "localhost" and not url.hash


def loopback_client_metadata(client_id: str) -> dict:
    """Metadata implied by an atproto loopback client_id's query params."""
    try:
        url = parse_url(client_id)
    except ValueError as exc:
        raise ClientMetadataError("client_id must be a URL") from exc
    if not _is_loopback_client_id(url):
        raise ClientMetadataError("not an AT Protocol loopback client_id")
    redirect_uri = url.param("redirect_uri")
    scope = url.param("scope")
    if scope is None:
        scope = "atproto"
    if not redirect_uri:
        raise ClientMetadataError("loopback client_id requires redirect_uri")
    try:
        redirect = parse_url(redirect_uri)
    except ValueError as exc:
        raise ClientMetadataError("loopback redirect_uri is invalid") from exc
    if redirect.protocol != "http:" or redirect.hostname not in ("127.0.0.1", "localhost", "[::1]"):
        raise ClientMetadataError("loopback redirect_uri must be loopback http")
    if "atproto" not in _scopes(scope):
        raise ClientMetadataError("loopback scope must include atproto")
    return {
        "client_id": client_id,
        "client_name": "loopback oauth client",
        "application_type": "native",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "redirect_uris": [redirect_uri],
        "scope": scope,
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": True,
    }


def _validate_client_id(client_id: str, hostname: str):
    try:
        url = parse_url(client_id)
    except ValueError as exc:
        raise ClientMetadataError("client_id must be a URL") from exc
    if url.hash:
        raise ClientMetadataError("client_id must not include a fragment")
    if _is_loopback_client_id(url):
        return url
    if url.protocol != "https:":
        raise ClientMetadataError("client_id must use https")
    if url.hostname == hostname and url.href != f"https://{hostname}/client-metadata.json":
        raise ClientMetadataError("client_id must not use the roost origin")
    return url


def validate_client_metadata(client_id: str, body) -> dict:
    if not isinstance(body, dict):
        raise ClientMetadataError("client metadata must be a JSON object")
    if body.get("client_id") != client_id:
        raise ClientMetadataError("client metadata client_id mismatch")
    if body.get("dpop_bound_access_tokens") is not True:
        raise ClientMetadataError("client metadata must require DPoP-bound access tokens")
    if not isinstance(body.get("scope"), str) or "atproto" not in _scopes(body["scope"]):
        raise ClientMetadataError("client metadata scope must include atproto")
    if not _is_string_list(body.get("response_types")) or "code" not in body["response_types"]:
        raise ClientMetadataError("client metadata response_types must include code")
    if not _is_string_list(body.get("grant_types")) or "authorization_code" not in body["grant_types"]:
        raise ClientMetadataError("client metadata grant_types must include authorization_code")
    if not _is_string_list(body.get("redirect_uris")) or not body["redirect_uris"]:
        raise ClientMetadataError("client metadata redirect_uris must be a non-empty string array")
    auth_method = body.get("token_endpoint_auth_method")
    if "token_endpoint_auth_method" in body and auth_method not in ("none", "private_key_jwt"):
        raise ClientMetadataError("unsupported token_endpoint_auth_method")
    if "token_endpoint_auth_signing_alg" in body and body["token_endpoint_auth_signing_alg"] != "ES256":
        raise ClientMetadataError("unsupported token_endpoint_auth_signing_alg")
    if auth_method == "private_key_jwt":
        if "jwks" in body:
            _validate_jwks(body["jwks"])
        elif not isinstance(body.get("jwks_uri"), str) or not body["jwks_uri"].startswith("https://"):
            raise ClientMetadataError("private_key_jwt requires jwks or an https jwks_uri")
    return body


def _validate_jwks(jwks) -> None:
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise ClientMetadataError("client jwks must be a JWKS object")
    # A JWKS may also publish keys we can't use (other curves, encryption keys); keep it if any key is ES256-usable.
    if not any(_is_ec_public_jwk(key) for key in jwks["keys"]):
        raise ClientMetadataError("client jwks must contain an EC P-256 public key")
    if any(isinstance(key, dict) and "d" in key for key in jwks["keys"]):
        raise ClientMetadataError("client jwks must not contain private keys")


async def _fetch_json(url: str, env, timeout: float, what: str):
    try:
        response = await env.http.fetch(url, redirect="manual", timeout=timeout)
    except Exception as exc:
        raise ClientMetadataError(f"{what} fetch failed: {exc}") from exc
    if 300 <= response.status < 400:
        raise ClientMetadataError(f"{what} redirects are not allowed")
    if response.status != 200:
        raise ClientMetadataError(f"{what} fetch returned HTTP {response.status}")
    content_type = response.headers.get("content-type", "")
    if content_type.split(";")[0].strip().lower() not in ("application/json", "application/jwk-set+json"):
        raise ClientMetadataError(f"{what} content-type must be application/json")
    length = response.headers.get("content-length")
    if length is not None and length.isdigit() and int(length) > MAX_CLIENT_METADATA_BYTES:
        raise ClientMetadataError(f"{what} response body is too large")
    if len(response.body) > MAX_CLIENT_METADATA_BYTES:
        raise ClientMetadataError(f"{what} response body is too large")
    try:
        return json.loads(response.body)
    except ValueError as exc:
        raise ClientMetadataError(f"{what} response is invalid JSON") from exc


async def fetch_client_metadata(client_id: str, env, timeout: float = DEFAULT_TIMEOUT_S) -> dict:
    hostname = env.ROOKERY_HOSTNAME
    url = _validate_client_id(client_id, hostname)
    if client_id == ROOK_CLI_CLIENT_METADATA["client_id"]:
        return validate_client_metadata(client_id, ROOK_CLI_CLIENT_METADATA)
    if client_id == f"https://{hostname}/client-metadata.json":
        return validate_client_metadata(client_id, rook_cli_client_metadata(hostname))
    if url.hostname == "localhost" and url.protocol == "http:":
        return validate_client_metadata(client_id, loopback_client_metadata(client_id))

    cached = _cache.get(client_id)
    if cached and time.time() - cached[1] < CACHE_TTL_S:
        return cached[0]
    body = await _fetch_json(client_id, env, timeout, "client metadata")
    metadata = validate_client_metadata(client_id, body)
    if metadata.get("token_endpoint_auth_method") == "private_key_jwt" and "jwks" not in metadata:
        # Resolve jwks_uri here so client auth checks one inline key set; the cache TTL bounds key-rotation lag.
        jwks = await _fetch_json(metadata["jwks_uri"], env, timeout, "client jwks_uri")
        _validate_jwks(jwks)
        metadata = dict(metadata, jwks=jwks)
    _cache[client_id] = (metadata, time.time())
    return metadata


def _is_loopback_redirect(url) -> bool:
    return url.protocol == "http:" and url.hostname in ("127.0.0.1", "[::1]", "::1")


def match_redirect_uri(registered: str, presented: str) -> bool:
    try:
        registered_url = parse_url(registered)
        presented_url = parse_url(presented)
    except ValueError:
        return False
    if registered_url.hash or presented_url.hash:
        return False
    if _is_loopback_redirect(registered_url):
        # Loopback redirects may use any port (RFC 8252).
        return (
            presented_url.protocol == "http:"
            and presented_url.hostname == registered_url.hostname
            and presented_url.pathname == registered_url.pathname
            and presented_url.search == registered_url.search
        )
    return registered == presented


async def verify_client_auth(metadata: dict, client_assertion_type: str | None, client_assertion: str | None,
                             issuer: str, db, now: int) -> dict:
    auth_method = metadata.get("token_endpoint_auth_method") or "none"
    if auth_method == "none":
        if client_assertion or client_assertion_type:
            raise ClientAuthError("public clients must not send client assertions")
        return {"method": "none", "client_id": metadata["client_id"]}
    if client_assertion_type != CLIENT_ASSERTION_TYPE:
        raise ClientAuthError("invalid client_assertion_type")
    if not client_assertion:
        raise ClientAuthError("missing client_assertion")
    try:
        header, payload, signing_input, signature = parse_jwt(client_assertion)
    except JwtFormatError as exc:
        raise ClientAuthError("client assertion is malformed") from exc
    if header.get("alg") != "ES256":
        raise ClientAuthError("client assertion alg must be ES256")
    if header.get("jwk"):
        raise ClientAuthError("client assertion must use metadata jwks")
    keys = [key for key in (metadata.get("jwks") or {}).get("keys") or [] if _is_ec_public_jwk(key)]
    kid = header.get("kid")
    candidates = [key for key in keys if key.get("kid") == kid] if isinstance(kid, str) else keys
    if not candidates:
        raise ClientAuthError("client assertion key not found")
    valid = False
    for jwk in candidates:
        try:
            if _verify_es256(jwk, signature, signing_input):
                valid = True
                break
        except DpopError as exc:
            raise ClientAuthError("invalid client public key") from exc
    if not valid:
        raise ClientAuthError("client assertion signature verification failed")
    if payload.get("iss") != metadata["client_id"] or payload.get("sub") != metadata["client_id"]:
        raise ClientAuthError("client assertion subject mismatch")
    if payload.get("aud") != issuer:
        raise ClientAuthError("client assertion audience mismatch")
    if not is_number(payload.get("exp")) or payload["exp"] <= now:
        raise ClientAuthError("client assertion expired")
    if not is_number(payload.get("iat")):
        raise ClientAuthError("client assertion missing iat")
    if payload["iat"] > now + 60:
        raise ClientAuthError("client assertion iat is in the future")
    if not isinstance(payload.get("jti"), str) or not payload["jti"]:
        raise ClientAuthError("client assertion missing jti")
    jti_hash = sha256_b64url(f"client_assertion:{metadata['client_id']}:{payload['jti']}")
    if not await insert_dpop_jti(db, jti_hash, payload["exp"], now):
        raise ClientAuthError("client assertion replayed jti")
    return {"method": "private_key_jwt", "client_id": metadata["client_id"]}
