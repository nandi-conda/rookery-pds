# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""HTTP message signatures for space requests, as http-signature.ts in @atproto/space.

A delegation-token exchange signs `authorization` and names its P-256 did:key
in `keyid`; a space-credential request signs `authorization` and
`atproto-space-audience` with the key the credential's cnf.kid binds.
"""

import base64

from ..crypto import lib
from ..encoding import b58_decode, b58_encode
from ..keys import P256_DID_PREFIX
from .sfv import SfvError, parse_dictionary, serialize_inner_list

LABEL = "atproto-space"
ALG = "ecdsa-p256-sha256"


class SpaceSignatureError(Exception):
    code = "BadSpaceSignature"


def _p256_public(did_key: str):
    if not isinstance(did_key, str) or not did_key.startswith("did:key:z"):
        return None
    try:
        raw = b58_decode(did_key[len("did:key:z"):])
    except Exception:
        return None
    if not raw.startswith(P256_DID_PREFIX):
        return None
    try:
        return lib().ec.EllipticCurvePublicKey.from_encoded_point(lib().ec.SECP256R1(), raw[2:])
    except ValueError:
        return None


def signature_base(authorization: str, signature_input: str, audience: str | None = None) -> bytes:
    lines = [f'"authorization": {authorization.strip()}']
    if audience is not None:
        lines.append(f'"atproto-space-audience": {audience.strip()}')
    lines.append(f'"@signature-params": {signature_input}')
    return "\n".join(lines).encode()


def verify_space_signature(headers, key_id: str | None = None) -> str:
    """The did:key that signed; raises SpaceSignatureError. `headers.get(name)` is case-insensitive."""
    input_header, signature_header = headers.get("signature-input"), headers.get("signature")
    if not isinstance(input_header, str) or not isinstance(signature_header, str):
        raise SpaceSignatureError("missing or malformed signature headers")
    try:
        sig_input = parse_dictionary(input_header).get(LABEL)
        signature = parse_dictionary(signature_header).get(LABEL)
    except SfvError as exc:
        raise SpaceSignatureError("missing or malformed atproto-space signature") from exc
    if (not sig_input or sig_input[0] != "list" or not signature or signature[0] != "item"
            or not isinstance(signature[1], bytes) or signature[2]):
        raise SpaceSignatureError("missing or malformed atproto-space signature")

    _, components, params = sig_input
    expected = ["authorization"] if key_id is None else ["authorization", "atproto-space-audience"]
    if [value for value, _ in components] != expected or any(item_params for _, item_params in components) \
            or any(not isinstance(value, str) for value, _ in components):
        joined = ", ".join(f'"{name}"' for name in expected)
        raise SpaceSignatureError(f"signature must cover exactly {joined}, in order")
    if "alg" in params and params["alg"] != ALG:
        raise SpaceSignatureError(f"signature algorithm must be {ALG}")
    signing_key = key_id if key_id is not None else params.get("keyid")
    public = _p256_public(signing_key) if isinstance(signing_key, str) else None
    if public is None:
        raise SpaceSignatureError("signature key must be a P-256 did:key")
    if key_id is not None and "keyid" in params and params["keyid"] != key_id:
        raise SpaceSignatureError("signature keyid does not match the credential key")

    authorization = headers.get("authorization")
    if not isinstance(authorization, str) or not authorization:
        raise SpaceSignatureError('request requires exactly one "authorization" field')
    audience = None
    if key_id is not None:
        audience = headers.get("atproto-space-audience")
        if not isinstance(audience, str) or not audience:
            raise SpaceSignatureError('request requires exactly one "atproto-space-audience" field')

    base = signature_base(authorization, serialize_inner_list(components, params), audience)
    raw = signature[1]
    if len(raw) != 64:
        raise SpaceSignatureError("invalid HTTP message signature")
    der = lib().encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        public.verify(der, base, lib().ec.ECDSA(lib().hashes.SHA256()))
    except Exception as exc:
        raise SpaceSignatureError("invalid HTTP message signature") from exc
    return signing_key


class P256Keypair:
    """A P-256 key for signing space requests (used by clients and tests)."""

    def __init__(self, key=None):
        self._key = key or lib().ec.generate_private_key(lib().ec.SECP256R1())

    def did(self) -> str:
        point = self._key.public_key().public_bytes(
            lib().serialization.Encoding.X962, lib().serialization.PublicFormat.CompressedPoint
        )
        return "did:key:z" + b58_encode(P256_DID_PREFIX + point)

    def sign(self, message: bytes) -> bytes:
        r, s = lib().decode_dss_signature(self._key.sign(message, lib().ec.ECDSA(lib().hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def create_space_sig_headers(key: P256Keypair, authorization: str, audience: str | None = None) -> dict:
    if audience is None:
        signature_input = f'("authorization");keyid="{key.did()}"'
    else:
        signature_input = '("authorization" "atproto-space-audience")'
    signature = key.sign(signature_base(authorization, signature_input, audience))
    headers = {
        "authorization": authorization,
        "signature-input": f"{LABEL}={signature_input}",
        "signature": f"{LABEL}=:{base64.b64encode(signature).decode()}:",
    }
    if audience is not None:
        headers["atproto-space-audience"] = audience
    return headers
