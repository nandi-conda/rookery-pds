# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""WelcomeMat authentication: an RS256 `dpop+jwt` proof plus a `wm+jwt`
access token bound to the same key and to the current terms of service."""

import json
import re
import time

from .encoding import sha256_b64url
from .urls import parse_url
from .jwt import JwtFormatError, is_number, parse_jwt, rs256_verify, rsa_public_key


class AuthError(ValueError):
    pass


def jwk_thumbprint(jwk: dict) -> str:
    canonical = json.dumps({"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}, separators=(",", ":"))
    return sha256_b64url(canonical)


def validate_and_import_key(jwk) -> object:
    if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
        raise AuthError("key must be RSA")
    if not jwk.get("n") or not jwk.get("e"):
        raise AuthError("invalid RSA key: missing n or e")
    try:
        key = rsa_public_key(jwk["n"], jwk["e"])
    except (ValueError, TypeError) as exc:
        raise AuthError("invalid RSA public key") from exc
    modulus_bits = (key.public_numbers().n.bit_length() + 7) // 8 * 8
    if modulus_bits != 4096:
        raise AuthError(f"key must be 4096-bit RSA (got {modulus_bits}-bit)")
    return key


def _origin_and_path(url: str) -> str:
    try:
        parsed = parse_url(url)
    except ValueError as exc:
        raise AuthError("invalid request URL") from exc
    return parsed.origin + parsed.pathname


def validate_dpop_proof(dpop_jwt: str, method: str, url: str, access_token: str | None) -> dict:
    """{jwk, key, thumbprint} for a valid proof; raises AuthError otherwise."""
    try:
        header, payload, signing_input, signature = parse_jwt(dpop_jwt)
    except JwtFormatError as exc:
        raise AuthError("invalid DPoP proof: malformed JWT") from exc
    if header.get("typ") != "dpop+jwt":
        raise AuthError("invalid DPoP proof: typ must be dpop+jwt")
    if header.get("alg") != "RS256":
        raise AuthError("invalid DPoP proof: alg must be RS256")
    if not header.get("jwk"):
        raise AuthError("invalid DPoP proof: missing jwk")
    key = validate_and_import_key(header["jwk"])
    if not payload.get("jti"):
        raise AuthError("invalid DPoP proof: missing jti")
    if payload.get("htm") != method:
        raise AuthError(f"invalid DPoP proof: htm must be {method}")
    if payload.get("htu") != _origin_and_path(url):
        raise AuthError("invalid DPoP proof: htu does not match request URL")
    iat = payload.get("iat")
    if not iat or not is_number(iat):
        raise AuthError("invalid DPoP proof: missing or invalid iat")
    if abs(int(time.time()) - iat) > 300:
        raise AuthError("invalid DPoP proof: iat too far from current time")
    if access_token:
        if not isinstance(payload.get("ath"), str):
            raise AuthError("invalid DPoP proof: missing ath")
        if payload["ath"] != sha256_b64url(access_token):
            raise AuthError("invalid DPoP proof: ath does not match access token")
    if not rs256_verify(key, signature, signing_input):
        raise AuthError("invalid DPoP proof: signature verification failed")
    return {"jwk": header["jwk"], "key": key, "thumbprint": jwk_thumbprint(header["jwk"])}


def validate_access_token(token: str, dpop_key, service_origin: str, dpop_thumbprint: str, tos_text: str) -> dict:
    try:
        header, payload, signing_input, signature = parse_jwt(token)
    except JwtFormatError as exc:
        raise AuthError("invalid access token: malformed JWT") from exc
    if header.get("typ") != "wm+jwt":
        raise AuthError("invalid access token: typ must be wm+jwt")
    if header.get("alg") != "RS256":
        raise AuthError("invalid access token: alg must be RS256")
    if not payload.get("tos_hash"):
        raise AuthError("invalid access token: missing tos_hash")
    if payload.get("aud") != service_origin:
        raise AuthError("invalid access token: aud does not match service origin")
    cnf = payload.get("cnf")
    if not isinstance(cnf, dict) or not isinstance(cnf.get("jkt"), str):
        raise AuthError("invalid access token: missing cnf.jkt")
    if cnf["jkt"] != dpop_thumbprint:
        raise AuthError("invalid access token: cnf.jkt does not match DPoP key")
    if payload["tos_hash"] != sha256_b64url(tos_text):
        raise AuthError("invalid access token: tos_hash does not match current terms")
    if not rs256_verify(dpop_key, signature, signing_input):
        raise AuthError("invalid access token: signature verification failed")
    return payload


_HANDLE_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


def is_valid_handle(handle: str) -> bool:
    return bool(_HANDLE_RE.match(handle)) and len(handle) <= 64


def extract_bearer_token(auth_header: str | None) -> str | None:
    if not auth_header:
        return None
    match = re.match(r"^DPoP\s+(.+)$", auth_header, re.IGNORECASE | re.DOTALL)
    return match.group(1) if match else None

