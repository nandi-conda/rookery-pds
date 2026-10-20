# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Space request authentication: space credentials (`Atproto-Space` scheme plus
an HTTP message signature), delegation tokens (exchanged for credentials) and
inter-service auth JWTs (notifications between PDSes)."""

import re
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ..encoding import b64url_decode, sha256_b64url
from ..errors import XrpcError
from ..jwt import JwtFormatError, parse_jwt
from ..keys import verify_did_key_signature
from ..oauth import store
from ..oauth.client_metadata import ClientMetadataError, fetch_client_metadata
from ..syntax import is_valid_did
from .httpsig import SpaceSignatureError, verify_space_signature
from .identity import IdentityError, signing_key
from .refs import InvalidSpaceRef, SpaceRef, space_host_aud
from .tokens import SpaceTokenError, parse_token, verify_token

AUTH_SCHEME_RE = re.compile(r"^(\S+)\s+(\S+)$")
_revocations_ensured: set[int] = set()


async def ensure_revocations(env) -> None:
    """Credential revocations a space authority sent this repo host (D1, shared by all accounts)."""
    if id(env.db) in _revocations_ensured:
        return
    await env.db.run("""CREATE TABLE IF NOT EXISTS revoked_space_credentials (
  space TEXT NOT NULL,
  jti TEXT NOT NULL,
  revoked_at TEXT NOT NULL,
  PRIMARY KEY (space, jti)
)""")
    _revocations_ensured.add(id(env.db))


def auth_required(message: str, code: str = "AuthRequired") -> XrpcError:
    return XrpcError(code, message, 401)


def auth_scheme(request) -> str | None:
    header = request.header("authorization")
    match = AUTH_SCHEME_RE.match(header or "")
    return match.group(1).lower() if match else None


def _token(request, scheme: str) -> str:
    match = AUTH_SCHEME_RE.match(request.header("authorization") or "")
    if not match or match.group(1).lower() != scheme.lower():
        raise auth_required(f"missing {scheme} authorization", "MissingJwt")
    return match.group(2)


def _space_from_sub(sub: str) -> SpaceRef:
    try:
        return SpaceRef.parse(sub)
    except InvalidSpaceRef as exc:
        raise auth_required(f"space token subject is not a space URI: {sub}", "BadJwtSub") from exc


async def _verify(env, token_type: str, jwt: str) -> dict:
    async def get_key(iss: str, kid: str | None, force_refresh: bool) -> str:
        if not kid:
            raise SpaceTokenError('missing token "kid"')
        key_id = kid.removeprefix("#")
        if key_id not in ("atproto", "atproto_space"):
            raise SpaceTokenError(f'unsupported space token "kid": {kid}')
        try:
            return await signing_key(env, iss, key_id, force_refresh)
        except IdentityError as exc:
            raise SpaceTokenError(str(exc), "BadJwtIss") from exc

    try:
        _, payload = await verify_token(token_type, jwt, get_key)
    except SpaceTokenError as exc:
        raise auth_required(str(exc), exc.code) from exc
    return payload


async def verify_space_credential(request, env) -> dict:
    """{type: "space_credential", iss, audience, space, jti} for an `Atproto-Space` request."""
    payload = await _verify(env, "credential", _token(request, "Atproto-Space"))
    space = _space_from_sub(payload["sub"])
    if payload["iss"] != space.did:
        raise auth_required("space credential issuer is not the space authority", "BadJwtIss")
    audience = request.header("atproto-space-audience")
    if not is_valid_did(audience):
        raise auth_required("missing or invalid space audience DID", "BadSpaceSignature")
    try:
        verify_space_signature(request.headers, payload["cnf"]["kid"])
    except SpaceSignatureError as exc:
        raise auth_required(str(exc), exc.code) from exc
    await ensure_revocations(env)
    revoked = await env.db.first(
        "SELECT 1 AS x FROM revoked_space_credentials WHERE space = ? AND jti = ?", str(space), payload["jti"]
    )
    if revoked:
        raise auth_required("space credential has been revoked", "CredentialRevoked")
    return {"type": "space_credential", "iss": space.did, "audience": audience, "space": str(space)}


async def verify_delegation(request, env) -> dict:
    """{user_did, space, key_id} for a getSpaceCredential call."""
    token = _token(request, "Bearer")
    payload = await _verify(env, "delegation", token)
    space = _space_from_sub(payload["sub"])
    if payload.get("aud") != space_host_aud(space.did):
        raise auth_required("delegation token audience does not match the space authority", "BadJwtAudience")
    if not is_valid_did(payload["iss"]):
        raise auth_required("delegation token issuer is not a DID", "BadJwtIss")
    try:
        key_id = verify_space_signature(request.headers)
    except SpaceSignatureError as exc:
        raise auth_required(str(exc), exc.code) from exc
    await store.init_oauth(env.db)
    jti_hash = sha256_b64url(f"space-delegation:{payload['iss']}:{payload['jti']}")
    if not await store.insert_dpop_jti(env.db, jti_hash, int(payload["exp"]) + 5, int(time.time())):
        raise auth_required("delegation token has already been used", "JwtReplayed")
    return {"user_did": payload["iss"], "space": str(space), "key_id": key_id}


async def verify_service_auth(request, env, lxm: str) -> dict:
    """{iss, aud} of an inter-service JWT (`Authorization: Bearer`), signed by iss's atproto key."""
    token = _token(request, "Bearer")
    try:
        header, payload, signing_input, signature = parse_jwt(token)
    except JwtFormatError as exc:
        raise auth_required("malformed service auth token", "BadJwt") from exc
    if header.get("typ") in ("at+jwt", "refresh+jwt", "dpop+jwt"):
        raise auth_required("not a service auth token", "BadJwt")
    iss, aud, exp = payload.get("iss"), payload.get("aud"), payload.get("exp")
    if not isinstance(iss, str) or not isinstance(aud, str):
        raise auth_required("service auth token requires iss and aud", "BadJwt")
    if not isinstance(exp, (int, float)) or exp <= time.time():
        raise auth_required("service auth token expired", "JwtExpired")
    if payload.get("lxm") not in (None, lxm):
        raise auth_required("service auth token lxm does not match this method", "BadJwtLexiconMethod")
    issuer_did = iss.split("#", 1)[0]
    if header.get("alg") not in ("ES256K", "ES256"):
        raise auth_required("unsupported service auth alg", "BadJwtSignature")
    try:
        raw_sig = b64url_decode(signature)
        key = await signing_key(env, issuer_did)
        if not verify_did_key_signature(key, signing_input.encode(), raw_sig):
            key = await signing_key(env, issuer_did, force_refresh=True)
            if not verify_did_key_signature(key, signing_input.encode(), raw_sig):
                raise auth_required("service auth signature is invalid", "BadJwtSignature")
    except IdentityError as exc:
        raise auth_required(str(exc), "BadJwtIss") from exc
    return {"iss": issuer_did, "aud": aud}


def _jwk_public(jwk: dict) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("client attestation keys must be EC P-256")
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(b64url_decode(jwk["x"]), "big"), int.from_bytes(b64url_decode(jwk["y"]), "big"), ec.SECP256R1()
    )
    return numbers.public_key()


async def verify_client_attestation(env, attestation: str, aud: str) -> str:
    """The attested client_id: a client-signed JWT verified against its metadata jwks."""
    try:
        header, payload, signing_input, signature = parse_token("clientAttestation", attestation)
    except SpaceTokenError as exc:
        raise XrpcError("InvalidClientAttestation", str(exc)) from exc
    now = time.time()
    if payload.get("aud") != aud:
        raise XrpcError("InvalidClientAttestation", "client attestation audience does not match the space host")
    if now - 5 >= payload["exp"]:
        raise XrpcError("InvalidClientAttestation", "client attestation expired")
    if header.get("alg") != "ES256":
        raise XrpcError("InvalidClientAttestation", "client attestation must be ES256")
    client_id = payload["iss"]
    try:
        metadata = await fetch_client_metadata(client_id, env)
    except ClientMetadataError as exc:
        raise XrpcError("InvalidClientAttestation", f"client metadata: {exc}") from exc
    keys = (metadata.get("jwks") or {}).get("keys") or []
    candidates = [key for key in keys if not header.get("kid") or key.get("kid") == header.get("kid")]
    if len(signature) != 64:
        raise XrpcError("InvalidClientAttestation", "invalid client attestation signature")
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    for jwk in candidates:
        try:
            _jwk_public(jwk).verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        except Exception:
            continue
        await store.init_oauth(env.db)
        jti_hash = sha256_b64url(f"client-attestation:{client_id}:{payload['jti']}")
        if not await store.insert_dpop_jti(env.db, jti_hash, int(payload["exp"]) + 5, int(now)):
            raise XrpcError("InvalidClientAttestation", "client attestation has already been used")
        return client_id
    raise XrpcError("InvalidClientAttestation", "invalid client attestation signature")
