# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""HTTP message signatures for space credential use, as http-signature.ts in @atproto/space.

A request authorized by a space credential signs `authorization` and
`atproto-space-audience`, tagged `atproto-space-credential`, with the P-256 key
the credential's cnf.kid binds.
"""

import base64

from ..crypto import lib
from ..keys import P256Keypair, p256_did_key_point
from .sfv import SfvError, Token, parse_dictionary, serialize_inner_list

LABEL = "atproto-space-credential"
TAG = "atproto-space-credential"
ALG = "ecdsa-p256-sha256"
COMPONENTS = ["authorization", "atproto-space-audience"]


class SpaceSignatureError(Exception):
    code = "BadSpaceSignature"


def signature_base(authorization: str, audience: str, signature_input: str) -> bytes:
    lines = [
        f'"authorization": {authorization.strip()}',
        f'"atproto-space-audience": {audience.strip()}',
        f'"@signature-params": {signature_input}',
    ]
    return "\n".join(lines).encode()


def verify_credential_sig(headers, key_id: str) -> None:
    """Raises SpaceSignatureError. `headers.get(name)` is case-insensitive."""
    authorization = headers.get("authorization")
    if not isinstance(authorization, str) or not authorization:
        raise SpaceSignatureError('missing or malformed "authorization" field')
    audience = headers.get("atproto-space-audience")
    if not isinstance(audience, str) or not audience:
        raise SpaceSignatureError('missing or malformed "atproto-space-audience" field')
    input_header, signature_header = headers.get("signature-input"), headers.get("signature")
    if not isinstance(input_header, str) or not isinstance(signature_header, str):
        raise SpaceSignatureError("missing or malformed signature headers")
    try:
        sig_input = parse_dictionary(input_header).get(LABEL)
        signature = parse_dictionary(signature_header).get(LABEL)
    except SfvError as exc:
        raise SpaceSignatureError("missing or malformed signature headers") from exc
    if (not sig_input or sig_input[0] != "list" or not signature or signature[0] != "item"
            or not isinstance(signature[1], bytes) or signature[2]):
        raise SpaceSignatureError(f"missing or malformed {LABEL} signature")

    _, components, params = sig_input
    if [value for value, _ in components] != COMPONENTS or any(item_params for _, item_params in components) \
            or any(isinstance(value, Token) or not isinstance(value, str) for value, _ in components):
        raise SpaceSignatureError('signature must cover exactly ("authorization" "atproto-space-audience"), in order')
    if params.get("tag") != TAG or isinstance(params.get("tag"), Token):
        raise SpaceSignatureError(f'signature tag must be "{TAG}"')
    if "alg" in params and params["alg"] != ALG:
        raise SpaceSignatureError(f"signature algorithm must be {ALG}")
    if "keyid" in params and params["keyid"] != key_id:
        raise SpaceSignatureError("signature keyid does not match the credential key")
    point = p256_did_key_point(key_id)
    if point is None:
        raise SpaceSignatureError("signature key must be a P-256 did:key")

    base = signature_base(authorization, audience, serialize_inner_list(components, params))
    raw = signature[1]
    if len(raw) != 64:
        raise SpaceSignatureError("invalid HTTP message signature")
    c = lib()
    public = c.ec.EllipticCurvePublicKey.from_encoded_point(c.ec.SECP256R1(), point)
    der = c.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        public.verify(der, base, c.ec.ECDSA(c.hashes.SHA256()))
    except Exception as exc:
        raise SpaceSignatureError("invalid HTTP message signature") from exc


def create_space_sig_headers(key: P256Keypair, authorization: str, audience: str) -> dict:
    """The headers a client sends to use a space credential (used by tests)."""
    signature_input = f'("authorization" "atproto-space-audience");tag="{TAG}"'
    signature = key.sign(signature_base(authorization, audience, signature_input))
    return {
        "authorization": authorization,
        "atproto-space-audience": audience,
        "signature-input": f"{LABEL}={signature_input}",
        "signature": f"{LABEL}=:{base64.b64encode(signature).decode()}:",
    }
