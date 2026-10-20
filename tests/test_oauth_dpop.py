# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""OAuth DPoP proofs: ES256, htu binding, iat window, ath, jti replay, server nonces."""

import time
import uuid

import pytest

from oauth_client import EcKey
from rookery.encoding import sha256_b64url
from rookery.oauth import store
from rookery.oauth.dpop import DpopError, UseDpopNonceError, ec_jwk_thumbprint, validate_oauth_dpop_proof
from rookery.oauth.nonce import derive_dpop_nonce

SECRET = "test-oauth-nonce-secret"
HTU = "https://server.example/oauth/token"
RESOURCE = "https://server.example/xrpc/com.atproto.repo.createRecord"


def proof(key: EcKey, htu: str = HTU, access_token: str | None = None, nonce: str | None = None,
          header: dict | None = None, **payload_overrides) -> str:
    payload = {"jti": str(uuid.uuid4()), "htm": "POST", "htu": htu, "iat": int(time.time())}
    if access_token is not None:
        payload["ath"] = sha256_b64url(access_token)
    if nonce is not None:
        payload["nonce"] = nonce
    payload.update(payload_overrides)
    return key.jwt(dict({"typ": "dpop+jwt", "alg": "ES256", "jwk": key.jwk}, **(header or {})), payload)


@pytest.fixture
async def validate(env):
    await store.init_oauth(env.db)

    async def run(jwt: str, url: str = HTU, access_token: str | None = None, **options):
        return await validate_oauth_dpop_proof(jwt, "POST", url, access_token, db=env.db, nonce_secret=SECRET,
                                               now=int(time.time()), **options)
    return run


def nonce() -> str:
    return derive_dpop_nonce(SECRET, int(time.time()))


async def test_accepts_es256_and_computes_the_rfc7638_thumbprint(validate):
    key = EcKey()
    result = await validate(proof(key, nonce=nonce()))
    assert result["jwk"]["x"] == key.jwk["x"]
    assert ec_jwk_thumbprint(result["jwk"]) == key.thumbprint == result["thumbprint"]


async def test_rejects_rs256_alg(validate):
    with pytest.raises(DpopError, match="alg must be ES256"):
        await validate(proof(EcKey(), nonce=nonce(), header={"alg": "RS256"}))


async def test_htu_is_origin_plus_path_never_the_query(validate):
    key, request_url = EcKey(), HTU + "?foo=bar"
    assert (await validate(proof(key, nonce=nonce()), request_url))["payload"]["htu"] == HTU
    with pytest.raises(DpopError, match="htu must not include query or fragment"):
        await validate(proof(key, request_url, nonce=nonce()), request_url)


async def test_rejects_stale_iat(validate):
    with pytest.raises(DpopError, match="iat too far"):
        await validate(proof(EcKey(), nonce=nonce(), iat=int(time.time()) - 301))


async def test_rejects_wrong_ath(validate):
    with pytest.raises(DpopError, match="ath does not match"):
        await validate(proof(EcKey(), access_token="access-token", nonce=nonce(), ath="wrong"), access_token="access-token")


async def test_rejects_replayed_jti(validate):
    jwt = proof(EcKey(), nonce=nonce())
    assert await validate(jwt)
    with pytest.raises(DpopError, match="replayed jti"):
        await validate(jwt)


@pytest.mark.parametrize("bad_nonce", [None, "fabricated"])
async def test_missing_or_fabricated_nonce_asks_for_one(validate, bad_nonce):
    with pytest.raises(UseDpopNonceError):
        await validate(proof(EcKey(), nonce=bad_nonce))


async def test_resource_proofs_skip_the_nonce_but_still_bind_ath_and_jti(validate):
    key = EcKey()
    assert await validate(proof(key, RESOURCE, "resource-access-token"), RESOURCE, "resource-access-token", require_nonce=False)
    with pytest.raises(DpopError, match="ath does not match"):
        await validate(proof(key, RESOURCE, "resource-access-token"), RESOURCE, "other-access-token", require_nonce=False)
    jwt = proof(key, RESOURCE, "resource-access-token")
    assert await validate(jwt, RESOURCE, "resource-access-token", require_nonce=False)
    with pytest.raises(DpopError, match="replayed jti"):
        await validate(jwt, RESOURCE, "resource-access-token", require_nonce=False)
