# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""WelcomeMat primitives: encodings, JWT parsing, RSA key policy, DPoP proofs, access tokens."""

import json
import secrets
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from agent import _int_b64, _jwt, fresh_key
from roost.auth import AuthError, jwk_thumbprint, validate_access_token, validate_and_import_key, validate_dpop_proof
from roost.encoding import b64url_decode, b64url_encode, sha256_b64url
from roost.jwt import JwtFormatError, parse_jwt

URL = "https://example.com/path"


def public_jwk(key) -> dict:
    numbers = key.public_key().public_numbers()
    return {"kty": "RSA", "n": _int_b64(numbers.n), "e": _int_b64(numbers.e)}


def tamper(jwt: str) -> str:
    head, payload, signature = jwt.split(".")
    return f"{head}.{payload}.{'B' if signature[0] == 'A' else 'A'}{signature[1:]}"


@pytest.fixture(scope="module")
def key():
    return fresh_key()


def dpop(key, **overrides) -> str:
    payload = dict({"jti": "test-jti-123", "htm": "POST", "htu": URL, "iat": int(time.time())}, **overrides)
    return _jwt({"typ": "dpop+jwt", "alg": "RS256", "jwk": public_jwk(key)}, payload, key)


def test_base64url_round_trips_bytes_and_text():
    data = secrets.token_bytes(32)
    assert b64url_decode(b64url_encode(data)) == data
    assert b64url_decode(b64url_encode(b"rookery auth")).decode() == "rookery auth"


def test_sha256_of_empty_string():
    assert sha256_b64url("") == "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"


def test_parses_a_three_part_jwt():
    header, payload = {"typ": "wm+jwt", "alg": "RS256"}, {"sub": "did:plc:test"}
    head = b64url_encode(json.dumps(header).encode())
    body = b64url_encode(json.dumps(payload).encode())
    assert parse_jwt(f"{head}.{body}.test-signature") == (header, payload, f"{head}.{body}", "test-signature")


def test_rejects_a_two_part_jwt():
    with pytest.raises(JwtFormatError, match="expected 3 parts"):
        parse_jwt("one.two")


def test_rfc7638_thumbprint_is_stable(key):
    first = jwk_thumbprint(public_jwk(key))
    assert first and all(c.isalnum() or c in "-_" for c in first)
    assert jwk_thumbprint(public_jwk(key)) == first


def test_key_policy_accepts_rsa_4096(key):
    assert validate_and_import_key(public_jwk(key)).key_size == 4096


def test_key_policy_rejects_rsa_2048():
    small = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AuthError, match="4096-bit"):
        validate_and_import_key(public_jwk(small))


def test_key_policy_rejects_missing_n(key):
    jwk = public_jwk(key)
    del jwk["n"]
    with pytest.raises(AuthError, match="missing n or e"):
        validate_and_import_key(jwk)


def test_valid_dpop_proof(key):
    result = validate_dpop_proof(dpop(key), "POST", URL, None)
    assert result["jwk"] == public_jwk(key)
    assert result["thumbprint"] == jwk_thumbprint(public_jwk(key))


def test_dpop_proof_with_access_token_hash(key):
    assert validate_dpop_proof(dpop(key, ath=sha256_b64url("access-token")), "POST", URL, "access-token")["jwk"] == public_jwk(key)


@pytest.mark.parametrize("make,token,message", [
    (lambda key: tamper(dpop(key)), None, "signature verification failed"),
    (lambda key: dpop(key, iat=int(time.time()) - 600), None, "iat too far"),
    (lambda key: dpop(key, ath="wrong"), "access-token", "ath does not match"),
])
def test_dpop_proof_rejections(key, make, token, message):
    with pytest.raises(AuthError, match=message):
        validate_dpop_proof(make(key), "POST", URL, token)


def access_token(key, **overrides) -> str:
    payload = dict({"tos_hash": sha256_b64url("test-tos"), "aud": "https://example.com",
                    "cnf": {"jkt": jwk_thumbprint(public_jwk(key))}}, **overrides)
    return _jwt({"typ": "wm+jwt", "alg": "RS256"}, payload, key)


def test_valid_access_token(key):
    thumbprint = jwk_thumbprint(public_jwk(key))
    payload = validate_access_token(access_token(key), key.public_key(), "https://example.com", thumbprint, "test-tos")
    assert payload["aud"] == "https://example.com" and payload["cnf"] == {"jkt": thumbprint}


def test_access_token_with_a_bad_signature(key):
    with pytest.raises(AuthError, match="signature verification failed"):
        validate_access_token(tamper(access_token(key)), key.public_key(), "https://example.com",
                              jwk_thumbprint(public_jwk(key)), "test-tos")
