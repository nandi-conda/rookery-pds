# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Compact JWT parsing and RS256 verification shared by WelcomeMat and Access."""

import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .encoding import b64url_decode


class JwtFormatError(ValueError):
    pass


def parse_jwt(token: str) -> tuple[dict, dict, str, str]:
    """(header, payload, signing_input, signature) of a compact JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        raise JwtFormatError("invalid JWT: expected 3 parts")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except ValueError as exc:
        raise JwtFormatError("invalid JWT") from exc
    return header, payload, f"{parts[0]}.{parts[1]}", parts[2]


def rsa_public_key(n: str, e: str) -> rsa.RSAPublicKey:
    numbers = rsa.RSAPublicNumbers(int.from_bytes(b64url_decode(e), "big"), int.from_bytes(b64url_decode(n), "big"))
    return numbers.public_key()


def rs256_verify(key: rsa.RSAPublicKey, signature_b64url: str, signing_input: str) -> bool:
    try:
        key.verify(b64url_decode(signature_b64url), signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


def is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)
