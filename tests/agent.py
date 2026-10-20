# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""A WelcomeMat agent for tests: an RSA-4096 key, its wm+jwt access token,
and DPoP proofs, as a real agent would build them."""

import json
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from roost.encoding import b64url_encode, sha256_b64url


def _int_b64(value: int) -> str:
    return b64url_encode(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def _jwt(header: dict, payload: dict, key) -> str:
    signing_input = ".".join(
        b64url_encode(json.dumps(part, separators=(",", ":")).encode()) for part in (header, payload)
    )
    signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{b64url_encode(signature)}"


_KEY_CACHE = Path(__file__).resolve().parent / ".keycache"
_used = 0


def fresh_key():
    """A distinct RSA-4096 key per call. Generating one takes ~0.5s, so keys are
    cached on disk between runs (tests/.keycache, never committed)."""
    global _used
    _KEY_CACHE.mkdir(exist_ok=True)
    path = _KEY_CACHE / f"{_used}.pem"
    _used += 1
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
    return key


class Agent:
    def __init__(self, origin: str, tos_text: str, key=None):
        self.origin = origin
        self.tos_text = tos_text
        self.key = key or fresh_key()
        numbers = self.key.public_key().public_numbers()
        self.jwk = {"kty": "RSA", "n": _int_b64(numbers.n), "e": _int_b64(numbers.e)}
        canonical = json.dumps({"e": self.jwk["e"], "kty": "RSA", "n": self.jwk["n"]}, separators=(",", ":"))
        self.thumbprint = sha256_b64url(canonical)
        self.access_token = self.make_access_token()

    def make_access_token(self, tos_text: str | None = None) -> str:
        return _jwt({"typ": "wm+jwt", "alg": "RS256"}, {
            "tos_hash": sha256_b64url(tos_text if tos_text is not None else self.tos_text),
            "aud": self.origin,
            "cnf": {"jkt": self.thumbprint},
            "iat": int(time.time()),
        }, self.key)

    def tos_signature(self) -> str:
        return b64url_encode(self.key.sign(self.tos_text.encode(), padding.PKCS1v15(), hashes.SHA256()))

    def dpop(self, method: str, path: str, access_token: str | None = None, **overrides) -> str:
        payload = {"jti": str(uuid.uuid4()), "htm": method, "htu": f"{self.origin}{path}", "iat": int(time.time())}
        if access_token:
            payload["ath"] = sha256_b64url(access_token)
        payload.update(overrides)
        return _jwt({"typ": "dpop+jwt", "alg": "RS256", "jwk": self.jwk}, payload, self.key)

    def auth_headers(self, method: str, path: str) -> dict:
        return {
            "Authorization": f"DPoP {self.access_token}",
            "DPoP": self.dpop(method, path, self.access_token),
        }

    def signup_body(self, handle: str, **extra) -> dict:
        return dict({"handle": handle, "tos_signature": self.tos_signature(), "access_token": self.access_token}, **extra)
