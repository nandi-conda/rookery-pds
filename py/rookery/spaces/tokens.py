# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Space tokens, as credential.ts in @atproto/space: delegation tokens (a user's
PDS vouching that an app acts for them), space credentials (the authority's
grant to read a space, bound to a P-256 key) and client attestations."""

import json
import secrets
import time

from ..encoding import b64url_decode, b64url_encode
from ..keys import verify_did_key_signature
from ..syntax import is_valid_did

TOKEN_TYPES = {
    "delegation": {"typ": "atproto-space-delegation+jwt", "kid": "#atproto", "expires_in": 60,
                   "require_aud": True, "require_cnf": False},
    "credential": {"typ": "atproto-space-credential+jwt", "kid": "#atproto", "expires_in": 600,
                   "require_aud": False, "require_cnf": True},
    "clientAttestation": {"typ": "atproto-client-attestation+jwt", "kid": None, "expires_in": 60,
                          "require_aud": True, "require_cnf": False},
}
CLOCK_SKEW_S = 5
CREDENTIAL_MAX_AGE_S = 3600


class SpaceTokenError(Exception):
    def __init__(self, message: str, code: str = "BadJwt"):
        super().__init__(message)
        self.code = code


def _b64_json(value: dict) -> str:
    return b64url_encode(json.dumps(value, separators=(",", ":")).encode())


def build_token(token_type: str, sign, *, iss: str, sub: str, aud: str | None = None,
                key_id: str | None = None, alg: str = "ES256K") -> str:
    """`sign(bytes) -> bytes` is the issuer's key (compact r||s)."""
    spec = TOKEN_TYPES[token_type]
    if spec["require_aud"] and not aud:
        raise SpaceTokenError(f'a {token_type} token requires an "aud"')
    if spec["require_cnf"] and not key_id:
        raise SpaceTokenError(f'a {token_type} token requires a "keyId"')
    iat = int(time.time())
    header = {"alg": alg, "typ": spec["typ"]}
    if spec["kid"]:
        header["kid"] = spec["kid"]
    payload = {"iss": iss, "sub": sub}
    if aud:
        payload["aud"] = aud
    if key_id:
        payload["cnf"] = {"kid": key_id}
    payload.update(iat=iat, exp=iat + spec["expires_in"], jti=secrets.token_hex(8))
    signing_input = f"{_b64_json(header)}.{_b64_json(payload)}"
    return f"{signing_input}.{b64url_encode(sign(signing_input.encode()))}"


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def parse_token(token_type: str, jwt: str) -> tuple[dict, dict, bytes, bytes]:
    """Structural checks only: (header, payload, signing_input, signature)."""
    spec = TOKEN_TYPES[token_type]
    parts = jwt.split(".") if isinstance(jwt, str) else []
    if len(parts) != 3:
        raise SpaceTokenError("malformed token: expected 3 parts")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        signature = b64url_decode(parts[2])
    except ValueError as exc:
        raise SpaceTokenError(f"could not parse token: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise SpaceTokenError("could not parse token")
    if header.get("typ") != spec["typ"]:
        raise SpaceTokenError(f'wrong token type: expected "{spec["typ"]}", got "{header.get("typ")}"', "BadJwtType")
    if not isinstance(header.get("alg"), str) or not header["alg"]:
        raise SpaceTokenError('missing token "alg"')
    if not isinstance(payload.get("iss"), str) or not payload["iss"]:
        raise SpaceTokenError('missing token "iss"', "BadJwtIss")
    if not isinstance(payload.get("sub"), str) or not payload["sub"]:
        raise SpaceTokenError('missing token "sub"', "BadJwtSub")
    if not _is_number(payload.get("exp")):
        raise SpaceTokenError('missing token "exp"')
    if spec["require_aud"] and not payload.get("aud"):
        raise SpaceTokenError('missing token "aud"', "BadJwtAudience")
    cnf = payload.get("cnf")
    if spec["require_cnf"] and not (isinstance(cnf, dict) and is_valid_did(cnf.get("kid"))):
        raise SpaceTokenError('missing token "cnf.kid"', "BadJwtCnf")
    if not isinstance(payload.get("jti"), str) or not payload["jti"]:
        raise SpaceTokenError(f'a {token_type} token requires a "jti"')
    if token_type == "credential" and (
        not _is_number(payload.get("iat")) or payload["exp"] <= payload["iat"]
        or payload["exp"] - payload["iat"] > CREDENTIAL_MAX_AGE_S
    ):
        raise SpaceTokenError("invalid space credential lifetime")
    if token_type == "clientAttestation" and payload["iss"] != payload["sub"]:
        raise SpaceTokenError('client attestation "iss" and "sub" must both be the client_id', "BadJwtIss")
    return header, payload, f"{parts[0]}.{parts[1]}".encode(), signature


async def verify_token(token_type: str, jwt: str, get_signing_key, aud: str | None = None,
                       sub: str | None = None) -> tuple[dict, dict]:
    """`await get_signing_key(iss, kid, force_refresh) -> did:key`."""
    header, payload, signing_input, signature = parse_token(token_type, jwt)
    now = int(time.time())
    if token_type == "credential" and payload["iat"] > now + CLOCK_SKEW_S:
        raise SpaceTokenError("space credential issued in the future")
    if now - CLOCK_SKEW_S >= payload["exp"]:
        raise SpaceTokenError("token expired", "JwtExpired")
    if aud is not None and payload.get("aud") != aud:
        raise SpaceTokenError("token audience does not match this service", "BadJwtAudience")
    if sub is not None and payload["sub"] != sub:
        raise SpaceTokenError("token subject does not match the requested space", "BadJwtSub")
    if header["alg"] not in ("ES256K", "ES256"):
        raise SpaceTokenError(f'unsupported token "alg": {header["alg"]}', "BadJwtSignature")
    did_key = await get_signing_key(payload["iss"], header.get("kid"), False)
    if verify_did_key_signature(did_key, signing_input, signature):
        return header, payload
    fresh = await get_signing_key(payload["iss"], header.get("kid"), True)
    if fresh != did_key and verify_did_key_signature(fresh, signing_input, signature):
        return header, payload
    raise SpaceTokenError("invalid token signature", "BadJwtSignature")
