# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Client metadata documents, redirect matching, and private_key_jwt client auth."""

import json
import uuid

import pytest

from fakes import Env
from oauth_client import CLIENT_ASSERTION_TYPE, EcKey
from roost.net import HttpResponse
from roost.oauth import store
from roost.oauth.client_metadata import (
    ClientAuthError, ClientMetadataError, fetch_client_metadata, match_redirect_uri, reset_cache, verify_client_auth,
)

CLIENT_ID = "https://client.example/oauth-client.json"
JSON = {"content-type": "application/json"}


def valid_metadata(client_id: str = CLIENT_ID, **overrides) -> dict:
    return dict({
        "client_id": client_id,
        "redirect_uris": ["https://client.example/callback"],
        "response_types": ["code"],
        "grant_types": ["authorization_code"],
        "scope": "atproto",
        "dpop_bound_access_tokens": True,
    }, **overrides)


def serve(env, response: HttpResponse) -> None:
    env.http.routes[CLIENT_ID] = lambda *_: response


def json_response(body, status: int = 200) -> HttpResponse:
    return HttpResponse(status, json.dumps(body).encode(), JSON)


async def test_fetches_and_validates_with_manual_redirects(env):
    serve(env, json_response(valid_metadata()))
    metadata = await fetch_client_metadata(CLIENT_ID, env)
    assert metadata["client_id"] == CLIENT_ID and metadata["dpop_bound_access_tokens"] is True
    assert env.http.calls[0]["redirect"] == "manual"


@pytest.mark.parametrize("body", [
    valid_metadata("https://other.example/client.json"),
    valid_metadata(dpop_bound_access_tokens=False),
    valid_metadata(scope="transition:generic"),
    valid_metadata(grant_types=["refresh_token"]),
    valid_metadata(response_types=["token"]),
    valid_metadata(token_endpoint_auth_method="private_key_jwt"),
    valid_metadata(token_endpoint_auth_method="private_key_jwt", jwks_uri="http://client.example/jwks.json"),
], ids=["client-id-mismatch", "dpop-false", "no-atproto", "no-authorization-code", "no-code", "no-jwks",
        "http-jwks-uri"])
async def test_rejects_invalid_documents(env, body):
    serve(env, json_response(body))
    with pytest.raises(ClientMetadataError):
        await fetch_client_metadata(CLIENT_ID, env)


@pytest.mark.parametrize("client_id,message", [
    ("http://client.example/client.json", "https"),
    ("https://client.example/client.json#fragment", "fragment"),
    ("https://rookery.test/client.json", "roost origin"),
    ("https://rookery.test/client-metadata.json?alternate=1", "roost origin"),
])
async def test_rejects_bad_client_ids_before_fetching(env, client_id, message):
    with pytest.raises(ClientMetadataError, match=message):
        await fetch_client_metadata(client_id, env)
    assert env.http.calls == []


async def test_builtin_cli_metadata_resolves_locally():
    env = Env(ROOKERY_HOSTNAME="rook.host")
    metadata = await fetch_client_metadata("https://rook.host/client-metadata.json", env)
    assert metadata["client_id"] == "https://rook.host/client-metadata.json"
    assert env.http.calls == []


@pytest.mark.parametrize("response", [
    json_response(valid_metadata(), 302),
    json_response(valid_metadata(), 500),
    HttpResponse(200, b"plain", {"content-type": "text/plain"}),
    HttpResponse(200, b"[1,2,3]", JSON),
    HttpResponse(200, b"x" * (64 * 1024 + 1), JSON),
], ids=["redirect", "500", "text-plain", "array", "too-large"])
async def test_rejects_bad_fetch_responses(env, response):
    serve(env, response)
    with pytest.raises(ClientMetadataError):
        await fetch_client_metadata(CLIENT_ID, env)


JWKS_URI = "https://client.example/jwks.json"


async def test_resolves_jwks_uri_for_private_key_jwt(env):
    key = EcKey()
    jwks = {"keys": [{"kty": "RSA", "n": "x", "e": "AQAB", "kid": "rsa"}, dict(key.jwk, kid="client-key")]}
    serve(env, json_response(valid_metadata(token_endpoint_auth_method="private_key_jwt", jwks_uri=JWKS_URI)))
    env.http.routes[JWKS_URI] = lambda *_: json_response(jwks)
    metadata = await fetch_client_metadata(CLIENT_ID, env)
    assert metadata["jwks"] == jwks
    assert env.http.calls[1]["redirect"] == "manual"


@pytest.mark.parametrize("response", [
    json_response({"keys": []}, 404),
    json_response({"keys": [{"kty": "RSA", "n": "x", "e": "AQAB"}]}),
    json_response({"keys": [dict(EcKey().jwk, d="secret")]}),
], ids=["404", "no-ec-key", "private-key"])
async def test_rejects_bad_jwks_uri(env, response):
    serve(env, json_response(valid_metadata(token_endpoint_auth_method="private_key_jwt", jwks_uri=JWKS_URI)))
    env.http.routes[JWKS_URI] = lambda *_: response
    with pytest.raises(ClientMetadataError, match="jwks"):
        await fetch_client_metadata(CLIENT_ID, env)


async def test_cache_reset(env):
    serve(env, json_response(valid_metadata()))
    assert await fetch_client_metadata(CLIENT_ID, env)
    reset_cache()
    serve(env, json_response(valid_metadata(), 500))
    with pytest.raises(ClientMetadataError):
        await fetch_client_metadata(CLIENT_ID, env)


@pytest.mark.parametrize("registered,presented,matches", [
    ("https://client.example/cb", "https://client.example/cb", True),
    ("https://client.example/cb", "https://client.example/other", False),
    ("http://127.0.0.1:123/cb", "http://127.0.0.1:456/cb", True),
    ("http://[::1]:123/cb", "http://[::1]:456/cb", True),
    ("http://127.0.0.1:123/cb", "https://127.0.0.1:456/cb", False),
    ("http://127.0.0.1:123/cb", "http://127.0.0.1:456/other", False),
    ("http://127.0.0.1:123/cb?a=1", "http://127.0.0.1:456/cb?a=2", False),
    ("https://rookery.test:123/cb", "https://rookery.test:456/cb", False),
])
def test_redirect_matching_allows_only_loopback_port_variance(registered, presented, matches):
    assert match_redirect_uri(registered, presented) is matches


# private_key_jwt

ISSUER = "https://rookery.test"
NOW = 1_700_000_000


def metadata_and_assertion(signer: EcKey | None = None, **overrides):
    key = EcKey()
    metadata = valid_metadata(token_endpoint_auth_method="private_key_jwt", token_endpoint_auth_signing_alg="ES256",
                              jwks={"keys": [dict(key.jwk, kid="client-key")]})
    assertion = (signer or key).jwt({"alg": "ES256", "kid": "client-key"}, dict({
        "iss": CLIENT_ID, "sub": CLIENT_ID, "aud": ISSUER, "exp": NOW + 300, "iat": NOW, "jti": str(uuid.uuid4()),
    }, **overrides))
    return metadata, assertion


@pytest.fixture
async def db(env):
    await store.init_oauth(env.db)
    return env.db


async def test_accepts_a_valid_assertion(db):
    metadata, assertion = metadata_and_assertion()
    assert await verify_client_auth(metadata, CLIENT_ASSERTION_TYPE, assertion, ISSUER, db, NOW) == {
        "method": "private_key_jwt", "client_id": CLIENT_ID}


@pytest.mark.parametrize("make", [
    lambda: metadata_and_assertion(aud="https://wrong.test"),
    lambda: metadata_and_assertion(EcKey()),
], ids=["wrong-audience", "other-key"])
async def test_rejects_bad_assertions(db, make):
    metadata, assertion = make()
    with pytest.raises(ClientAuthError):
        await verify_client_auth(metadata, CLIENT_ASSERTION_TYPE, assertion, ISSUER, db, NOW)


async def test_public_client_ignores_a_sent_assertion(db):
    _, assertion = metadata_and_assertion()
    assert await verify_client_auth(valid_metadata(), CLIENT_ASSERTION_TYPE, assertion, ISSUER, db, NOW) == {
        "method": "none", "client_id": CLIENT_ID}


async def test_rejects_a_replayed_assertion_jti(db):
    metadata, assertion = metadata_and_assertion()
    assert await verify_client_auth(metadata, CLIENT_ASSERTION_TYPE, assertion, ISSUER, db, NOW)
    with pytest.raises(ClientAuthError):
        await verify_client_auth(metadata, CLIENT_ASSERTION_TYPE, assertion, ISSUER, db, NOW)
