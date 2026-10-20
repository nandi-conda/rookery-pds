# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""OAuth DPoP proofs: ES256 over a P-256 JWK, server nonces, jti replay guard."""

import json
from ..urls import parse_url

from ..auth import _origin_and_path
from ..crypto import lib
from ..encoding import b64url_decode, sha256_b64url
from ..jwt import JwtFormatError, is_number, parse_jwt
from .nonce import derive_dpop_nonce, is_valid_dpop_nonce
from .store import insert_dpop_jti


class DpopError(ValueError):
    pass


class UseDpopNonceError(DpopError):
    def __init__(self, nonce: str, message: str = "DPoP nonce required"):
        super().__init__(message)
        self.nonce = nonce


def ec_jwk_thumbprint(jwk: dict) -> str:
    canonical = json.dumps({"crv": "P-256", "kty": "EC", "x": jwk["x"], "y": jwk["y"]}, separators=(",", ":"))
    return sha256_b64url(canonical)


def _is_ec_public_jwk(jwk) -> bool:
    return (
        isinstance(jwk, dict)
        and jwk.get("kty") == "EC"
        and jwk.get("crv") == "P-256"
        and isinstance(jwk.get("x"), str)
        and isinstance(jwk.get("y"), str)
        and "d" not in jwk
    )


def _verify_es256(jwk: dict, signature_b64url: str, signing_input: str) -> bool:
    c = lib()
    try:
        x = int.from_bytes(b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(b64url_decode(jwk["y"]), "big")
        key = c.ec.EllipticCurvePublicNumbers(x, y, c.ec.SECP256R1()).public_key()
    except ValueError as exc:
        raise DpopError("invalid DPoP proof: invalid EC public key") from exc
    try:
        raw = b64url_decode(signature_b64url)
    except ValueError:
        return False
    if len(raw) != 64:
        return False
    der = c.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        key.verify(der, signing_input.encode(), c.ec.ECDSA(c.hashes.SHA256()))
        return True
    except c.InvalidSignature:
        return False


async def validate_oauth_dpop_proof(dpop_jwt: str, method: str, url: str, access_token: str | None, *,
                                    db, nonce_secret: str, now: int, require_nonce: bool = True) -> dict:
    """{jwk, thumbprint, payload}; raises DpopError (UseDpopNonceError for a missing/stale nonce)."""
    try:
        header, payload, signing_input, signature = parse_jwt(dpop_jwt)
    except JwtFormatError as exc:
        raise DpopError("invalid DPoP proof: malformed JWT") from exc
    if header.get("typ") != "dpop+jwt":
        raise DpopError("invalid DPoP proof: typ must be dpop+jwt")
    if header.get("alg") != "ES256":
        raise DpopError("invalid DPoP proof: alg must be ES256")
    jwk = header.get("jwk")
    if not _is_ec_public_jwk(jwk):
        raise DpopError("invalid DPoP proof: missing or invalid EC public jwk")
    if not isinstance(payload.get("jti"), str) or not payload["jti"]:
        raise DpopError("invalid DPoP proof: missing jti")
    if not isinstance(payload.get("htm"), str):
        raise DpopError("invalid DPoP proof: missing htm")
    if not isinstance(payload.get("htu"), str):
        raise DpopError("invalid DPoP proof: missing htu")
    if not is_number(payload.get("iat")):
        raise DpopError("invalid DPoP proof: missing or invalid iat")

    if require_nonce:
        nonce = payload.get("nonce")
        if not isinstance(nonce, str) or not nonce or not is_valid_dpop_nonce(nonce_secret, nonce, now):
            raise UseDpopNonceError(derive_dpop_nonce(nonce_secret, now))

    if not _verify_es256(jwk, signature, signing_input):
        raise DpopError("invalid DPoP proof: signature verification failed")
    if payload["htm"] != method:
        raise DpopError(f"invalid DPoP proof: htm must be {method}")
    try:
        htu = parse_url(payload["htu"])
    except ValueError as exc:
        raise DpopError("invalid DPoP proof: htu must be a URL") from exc
    if htu.search or htu.hash:
        raise DpopError("invalid DPoP proof: htu must not include query or fragment")
    if payload["htu"] != _origin_and_path(url):
        raise DpopError("invalid DPoP proof: htu does not match request URL")
    if abs(now - payload["iat"]) > 300:
        raise DpopError("invalid DPoP proof: iat too far from current time")
    if access_token is not None:
        if not isinstance(payload.get("ath"), str):
            raise DpopError("invalid DPoP proof: missing ath")
        if payload["ath"] != sha256_b64url(access_token):
            raise DpopError("invalid DPoP proof: ath does not match access token")

    jti_hash = sha256_b64url(f"dpop:{payload['jti']}")
    if not await insert_dpop_jti(db, jti_hash, now + 600, now):
        raise DpopError("invalid DPoP proof: replayed jti")
    return {"jwk": jwk, "thumbprint": ec_jwk_thumbprint(jwk), "payload": payload}
