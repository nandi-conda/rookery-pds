# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""OAuth end to end: PAR, consent, token, refresh, revoke, and resource access."""

import json
import time

import pytest

from agent import Agent
from conftest import ORIGIN, tos_text, unique
from fakes import query_of
from oauth_client import (
    AUTHORIZE_PATH, AUTHORIZE_URL, CLIENT_ASSERTION_TYPE, REVOKE_PATH, EcKey, authorize_code, client_metadata,
    consent_headers, do_par, exchange_code, new_client_id, oauth_headers, par_form, post_with_nonce, refresh,
    serve_metadata, token_success,
)
from roost.encoding import sha256_b64url
from roost.net import HttpResponse
from roost.oauth import store

CREATE = "/xrpc/com.atproto.repo.createRecord"


@pytest.fixture
def registered(env):
    """Serve metadata for a fresh client id; returns (client_id, redirect_uri)."""
    def register(prefix: str = "client", redirect_uris: list[str] | None = None, **overrides):
        client_id = new_client_id(prefix)
        serve_metadata(env, client_id, client_metadata(client_id, **(
            {"redirect_uris": redirect_uris} if redirect_uris else {}), **overrides))
        return client_id
    return register


async def code_row(env, code: str):
    return await env.db.first("SELECT did, dpop_jkt, exp FROM oauth_codes WHERE code_hash = ?", sha256_b64url(code))


async def code_row_for_redirect(env, redirect_uri: str):
    return await env.db.first("SELECT code_hash FROM oauth_codes WHERE redirect_uri = ?", redirect_uri)


async def par_row(env, request_uri: str):
    return await env.db.first("SELECT 1 FROM oauth_par_requests WHERE request_uri = ?", request_uri)


@pytest.fixture
def issue(client, enroll, registered):
    async def issue_token(scope: str = "atproto repo:com.example.test"):
        rook = await enroll()
        redirect_uri = f"http://127.0.0.1/callback?case={unique('token')}"
        client_id = registered("token", [redirect_uri])
        par = await do_par(client, client_id, redirect_uri, scope=scope)
        code = await authorize_code(client, par, rook.agent)
        return rook, par, token_success(await exchange_code(client, par, code))
    return issue_token


async def create_with_oauth(client, par, token, collection: str, rkey: str, dpop: str | None = None):
    headers = oauth_headers(par.key, "POST", CREATE, token["access_token"])
    if dpop is not None:
        headers["dpop"] = dpop
    return await client.post(CREATE, json_body={
        "repo": token["sub"], "collection": collection, "rkey": rkey,
        "record": {"text": rkey, "createdAt": "2026-01-01T00:00:00Z"},
    }, headers=headers)


# Authorize

async def test_happy_path_end_to_end(client, env, enroll, registered):
    rook = await enroll()
    redirect_uri = f"http://127.0.0.1/callback?case={unique('happy')}"
    client_id = registered("happy", [redirect_uri])
    par = await do_par(client, client_id, redirect_uri)
    assert any(call["url"] == client_id for call in env.http.calls)

    before = int(time.time())
    response = await client.get(par.authorize_path(), headers=consent_headers(rook.agent))
    after = int(time.time())
    assert response.status == 302
    location = query_of(response.headers["location"])
    assert location["state"] == par.state
    assert location["iss"] == ORIGIN
    row = await code_row(env, location["code"])
    assert row["did"] == rook.did and row["dpop_jkt"] == par.key.thumbprint
    assert before + 50 <= row["exp"] <= after + 70
    assert await par_row(env, par.request_uri) is None


async def test_second_authed_get_for_the_same_request_uri_is_rejected(client, enroll, registered):
    rook = await enroll()
    par = await do_par(client, registered())
    assert (await client.get(par.authorize_path(), headers=consent_headers(rook.agent))).status == 302
    second = await client.get(par.authorize_path(), headers=consent_headers(rook.agent))
    assert second.status == 400
    assert second.json()["error"] == "invalid_request"


async def test_replayed_consent_proof_on_another_request_uri_is_rejected(client, env, enroll, registered):
    rook = await enroll()
    one, two = (f"http://127.0.0.1/callback?case={unique(n)}" for n in ("one", "two"))
    client_id = registered("replay", [one, two])
    par_one = await do_par(client, client_id, one)
    par_two = await do_par(client, client_id, two)
    headers = consent_headers(rook.agent)
    assert (await client.get(par_one.authorize_path(), headers=headers)).status == 302
    second = await client.get(par_two.authorize_path(), headers=headers)
    assert second.status == 401
    assert second.json()["error"] == "AuthFailed"
    assert await code_row_for_redirect(env, two) is None


async def test_previews_without_consuming_then_consents(client, enroll, registered):
    rook = await enroll()
    client_id = registered("preview")
    par = await do_par(client, client_id)
    preview = await client.get(par.authorize_path())
    assert preview.status == 200
    assert preview.json() == {
        "consent_request": {
            "client_id": client_id,
            "client_metadata": {"client_name": "Test Client", "client_uri": "https://client.example"},
            "scope": "atproto",
            "redirect_uri": "http://127.0.0.1/callback",
            "login_hint": None,
        },
        "how_to_consent": (
            "GET this URL again with an `Authorization: DPoP <wm+jwt>` header and a matching DPoP proof built from "
            "the granting account's welcome-mat credential to grant; the DPoP htu is origin + path only, without "
            "query or fragment; append deny=1 to refuse."
        ),
    }
    assert (await client.get(par.authorize_path(), headers=consent_headers(rook.agent))).status == 302


async def test_denial_redirects_and_mints_no_code(client, env, enroll, registered):
    rook = await enroll()
    redirect_uri = f"http://127.0.0.1/callback?case={unique('deny')}"
    par = await do_par(client, registered("deny", [redirect_uri]), redirect_uri)
    response = await client.get(par.authorize_path(deny=True), headers=consent_headers(rook.agent))
    assert response.status == 302
    location = query_of(response.headers["location"])
    assert location["error"] == "access_denied"
    assert location["state"] == par.state
    assert location["iss"] == ORIGIN
    assert await par_row(env, par.request_uri) is None
    assert await code_row_for_redirect(env, redirect_uri) is None


async def test_any_authorization_header_takes_the_consent_path(client, registered):
    par = await do_par(client, registered())
    response = await client.get(par.authorize_path(), headers={"authorization": "Bearer junk"})
    assert response.status == 401
    assert response.json()["error"] == "AuthRequired"


# Token, revoke, resource access

async def test_exchanges_a_code_stores_only_hashes_and_writes(client, env, issue):
    rook, par, token = await issue("atproto repo:com.example.test")
    assert token["scope"] == "atproto repo:com.example.test"
    assert token["sub"] == rook.did
    assert token["expires_in"] == 900
    access_q = "SELECT 1 FROM oauth_tokens WHERE access_token_hash = ?"
    refresh_q = "SELECT 1 FROM oauth_sessions WHERE refresh_token_hash = ?"
    assert await env.db.first(access_q, token["access_token"]) is None
    assert await env.db.first(refresh_q, token["refresh_token"]) is None
    assert await env.db.first(access_q, sha256_b64url(token["access_token"]))
    assert await env.db.first(refresh_q, sha256_b64url(token["refresh_token"]))
    assert (await create_with_oauth(client, par, token, "com.example.test", unique("w"))).status == 200


async def test_codes_are_consumed_on_pkce_failure_and_bound(client, enroll, registered):
    rook = await enroll()
    redirect_uri = f"http://127.0.0.1/callback?case={unique('bindings')}"
    client_id = registered("bindings", [redirect_uri])
    other_client_id = registered("other", [redirect_uri])

    async def fresh():
        par = await do_par(client, client_id, redirect_uri)
        return par, await authorize_code(client, par, rook.agent)

    def invalid_grant(response):
        assert response.status == 400 and response.json()["error"] == "invalid_grant", response.text

    par, code = await fresh()
    invalid_grant(await exchange_code(client, par, code, code_verifier="wrong-verifier"))
    invalid_grant(await exchange_code(client, par, code))

    par, code = await fresh()
    token_success(await exchange_code(client, par, code))
    invalid_grant(await exchange_code(client, par, code))

    par, code = await fresh()
    invalid_grant(await exchange_code(client, par, code, client_id=other_client_id))

    par, code = await fresh()
    invalid_grant(await exchange_code(client, par, code, redirect_uri="http://127.0.0.1/callback?case=wrong"))

    par, code = await fresh()
    invalid_grant(await exchange_code(client, par, code, key=EcKey()))


async def test_refresh_rotates_keeps_session_expiry_and_binds_jkt(client, env, issue):
    _, par, token = await issue()
    response = await refresh(client, par, token["refresh_token"], key=EcKey())
    assert response.status == 400 and response.json()["error"] == "invalid_grant"

    session_exp = int(time.time()) + 120
    await env.db.run("UPDATE oauth_sessions SET exp = ? WHERE refresh_token_hash = ?",
                     session_exp, sha256_b64url(token["refresh_token"]))
    before = int(time.time())
    refreshed = token_success(await refresh(client, par, token["refresh_token"]))
    after = int(time.time())
    assert session_exp - after <= refreshed["expires_in"] <= session_exp - before

    response = await refresh(client, par, token["refresh_token"])
    assert response.status == 400 and response.json()["error"] == "invalid_grant"
    again = token_success(await refresh(client, par, refreshed["refresh_token"]))
    assert again["refresh_token"] != refreshed["refresh_token"]


async def test_expired_session_blocks_resource_access(client, env, issue):
    _, par, token = await issue()
    await env.db.run("UPDATE oauth_sessions SET exp = 0 WHERE refresh_token_hash = ?", sha256_b64url(token["refresh_token"]))
    row = await env.db.first("SELECT exp FROM oauth_tokens WHERE access_token_hash = ?", sha256_b64url(token["access_token"]))
    assert row["exp"] > time.time()
    response = await create_with_oauth(client, par, token, "com.example.test", unique("expired"))
    assert response.status == 401 and response.json()["error"] == "InvalidToken"


async def test_revokes_access_and_refresh_tokens_and_ignores_garbage(client, issue):
    _, par, token = await issue()
    assert (await client.post(REVOKE_PATH, form={"token": token["access_token"]})).status == 200
    response = await create_with_oauth(client, par, token, "com.example.test", unique("revoked"))
    assert response.status == 401 and response.json()["error"] == "InvalidToken"
    response = await refresh(client, par, token["refresh_token"])
    assert response.status == 400 and response.json()["error"] == "invalid_grant"

    _, par, token = await issue()
    assert (await client.post(REVOKE_PATH, form={"token": token["refresh_token"]})).status == 200
    response = await create_with_oauth(client, par, token, "com.example.test", unique("revoked"))
    assert response.status == 401 and response.json()["error"] == "InvalidToken"

    assert (await client.post(REVOKE_PATH, form={"token": "garbage"})).status == 200


async def test_forged_and_replayed_resource_proofs_are_rejected(client, issue):
    _, par, token = await issue()
    proof = par.key.dpop("POST", ORIGIN + CREATE, token["access_token"])
    head, payload, signature = proof.split(".")
    forged = f"{head}.{payload}.{'B' if signature[0] == 'A' else 'A'}{signature[1:]}"
    response = await create_with_oauth(client, par, token, "com.example.test", unique("forged"), forged)
    assert response.status == 401 and response.json()["error"] == "InvalidToken"

    replay = par.key.dpop("POST", ORIGIN + CREATE, token["access_token"])
    assert (await create_with_oauth(client, par, token, "com.example.test", unique("one"), replay)).status == 200
    response = await create_with_oauth(client, par, token, "com.example.test", unique("two"), replay)
    assert response.status == 401 and response.json()["error"] == "InvalidToken"


async def test_scopes_gate_writes_and_blob_uploads(client, issue):
    def insufficient(response):
        assert response.status == 403 and response.json()["error"] == "InsufficientScope", response.text

    _, par, token = await issue("atproto repo:com.example.case")
    insufficient(await create_with_oauth(client, par, token, "com.example.Case", unique("case")))

    _, par, token = await issue("atproto repo:com.example.allowed")
    path = "/xrpc/com.atproto.repo.applyWrites"
    insufficient(await client.post(path, headers=oauth_headers(par.key, "POST", path, token["access_token"]), json_body={
        "repo": token["sub"],
        "writes": [
            {"$type": "com.atproto.repo.applyWrites#create", "collection": "com.example.allowed",
             "rkey": "allowed-create", "record": {"text": "allowed"}},
            {"$type": "com.atproto.repo.applyWrites#delete", "collection": "com.example.denied", "rkey": "denied-delete"},
        ],
    }))
    got = await client.get("/xrpc/com.atproto.repo.getRecord",
                           params={"repo": token["sub"], "collection": "com.example.allowed", "rkey": "allowed-create"})
    assert got.status == 404

    upload = "/xrpc/com.atproto.repo.uploadBlob"
    for scope, status in (("atproto repo:com.example.test", 403), ("atproto transition:generic", 200)):
        _, par, token = await issue(scope)
        response = await client.post(upload, body=b"blob bytes", headers=dict(
            oauth_headers(par.key, "POST", upload, token["access_token"]), **{"content-type": "text/plain"}))
        assert response.status == status, response.text

    _, par, token = await issue("atproto")
    insufficient(await create_with_oauth(client, par, token, "com.example.test", unique("atproto-only")))


async def test_service_auth_requires_a_matching_rpc_scope(client, issue):
    from roost.jwt import parse_jwt
    aud, lxm = "did:web:knot.rook.host", "sh.tangled.repo.create"
    path = "/xrpc/com.atproto.server.getServiceAuth"

    _, par, token = await issue("atproto transition:generic")
    response = await client.get(path, params={"aud": aud, "lxm": lxm},
                                headers=oauth_headers(par.key, "GET", path, token["access_token"]))
    assert response.status == 403 and response.json()["error"] == "InsufficientScope"

    _, par, token = await issue(f"atproto rpc:{lxm}?aud={aud}")
    exp = int(time.time()) + 120
    response = await client.get(path, params={"aud": aud, "lxm": lxm, "exp": str(exp)},
                                headers=oauth_headers(par.key, "GET", path, token["access_token"]))
    assert response.status == 200, response.text
    header, payload, _, signature = parse_jwt(response.json()["token"])
    assert {k: header.get(k) for k in ("typ", "alg", "kid")} == {"typ": "JWT", "alg": "ES256K", "kid": "#atproto"}
    assert {k: payload[k] for k in ("iss", "aud", "lxm", "exp")} == {"iss": token["sub"], "aud": aud, "lxm": lxm, "exp": exp}
    assert isinstance(payload["iat"], int) and isinstance(payload["jti"], str)
    assert signature


COLIBRI_APPVIEW = "did:web:api.colibri.social#colibri_appview"


def serve_permission_set(env, nsid: str, permissions: list) -> dict:
    """Publish `nsid` the way lexicon resolution finds it: DNS TXT -> did:web -> PDS record."""
    authority = "did:web:lex.colibri.test"
    calls = {"record": 0}

    def dns(method, url, headers, body):
        answer = [{"name": "_lexicon.colibri.social", "type": 16, "data": f'"did={authority}"'}]
        return HttpResponse(200, json.dumps({"Status": 0, "Answer": answer}).encode())

    def did_doc(method, url, headers, body):
        doc = {"id": authority, "service": [
            {"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://lexpds.test"}]}
        return HttpResponse(200, json.dumps(doc).encode())

    def record(method, url, headers, body):
        calls["record"] += 1
        assert query_of(url) == {"repo": authority, "collection": "com.atproto.lexicon.schema", "rkey": nsid}
        value = {"$type": "com.atproto.lexicon.schema", "lexicon": 1, "id": nsid,
                 "defs": {"main": {"type": "permission-set", "permissions": permissions}}}
        return HttpResponse(200, json.dumps({"uri": "at://x", "value": value}).encode())

    env.http.routes["https://cloudflare-dns.com/dns-query"] = dns
    env.http.routes["https://lex.colibri.test/.well-known/did.json"] = did_doc
    env.http.routes["https://lexpds.test/xrpc/com.atproto.repo.getRecord"] = record
    return calls


async def test_include_scopes_expand_permission_sets(client, env, issue):
    calls = serve_permission_set(env, "social.colibri.permissionAccount", [
        {"type": "permission", "resource": "repo", "action": ["create", "update", "delete"],
         "collection": ["social.colibri.actor.profile"]},
        {"type": "permission", "resource": "rpc", "inheritAud": True, "lxm": ["social.colibri.actor.getData"]},
    ])
    appview_calls = []
    env.http.routes["https://api.colibri.social/.well-known/did.json"] = lambda *_: HttpResponse(200, json.dumps({
        "id": "did:web:api.colibri.social", "service": [
            {"id": "#colibri_appview", "type": "ColibriAppView", "serviceEndpoint": "https://appview.colibri.test"}],
    }).encode())
    env.http.routes["https://appview.colibri.test/"] = lambda m, url, h, b: (
        appview_calls.append((url, h)) or HttpResponse(200, b'{"ok":true}', {"content-type": "application/json"}))

    scope = f"atproto include:social.colibri.permissionAccount?aud={COLIBRI_APPVIEW}"
    _, par, token = await issue(scope)
    assert token["scope"] == scope

    response = await create_with_oauth(client, par, token, "social.colibri.actor.profile", "self")
    assert response.status == 200, response.text
    response = await create_with_oauth(client, par, token, "social.colibri.community.message", unique("m"))
    assert response.status == 403 and response.json()["error"] == "InsufficientScope"

    def proxied(lxm: str, service: str = COLIBRI_APPVIEW):
        path = f"/xrpc/{lxm}"
        headers = dict(oauth_headers(par.key, "GET", path, token["access_token"]), **{"atproto-proxy": service})
        return client.get(path, headers=headers)

    response = await proxied("social.colibri.actor.getData")
    assert response.status == 200, response.text
    assert appview_calls[0][0] == "https://appview.colibri.test/xrpc/social.colibri.actor.getData"
    assert (await proxied("social.colibri.actor.listMutes")).status == 403
    assert (await proxied("social.colibri.actor.getData", "did:web:api.colibri.social#other")).status == 403
    assert calls["record"] == 1  # resolved once at PAR, then served from the D1 cache


async def test_par_rejects_unresolvable_permission_sets(client, env, registered):
    env.http.routes["https://cloudflare-dns.com/dns-query"] = lambda *_: HttpResponse(200, b'{"Status":3}')
    await par_rejected(client, registered(), "invalid_scope",
                       scope=f"atproto include:social.colibri.permissionAccount?aud={COLIBRI_APPVIEW}")


async def test_deactivated_accounts_lose_resource_access_and_refresh(client, env, issue):
    _, par, token = await issue()
    await env.db.run("UPDATE accounts SET active = 0 WHERE did = ?", token["sub"])
    response = await create_with_oauth(client, par, token, "com.example.test", unique("deactivated"))
    assert response.status == 401 and response.json()["error"] == "InvalidToken"
    response = await refresh(client, par, token["refresh_token"])
    assert response.status == 400 and response.json()["error"] == "invalid_grant"


# PAR validation

async def par_rejected(client, client_id: str, error: str, status: int = 400, **overrides):
    form, _ = par_form(client_id, **overrides)
    response = await post_with_nonce(client, "/oauth/par", form, EcKey())
    assert response.status == status, response.text
    assert response.json()["error"] == error


@pytest.mark.parametrize("overrides,error", [
    ({"redirect_uri": "http://127.0.0.1/other"}, "invalid_request"),
    ({"code_challenge_method": "plain"}, "invalid_request"),
    ({"scope": "transition:generic"}, "invalid_scope"),
    ({"scope": "atproto include:app.bsky"}, "invalid_scope"),
    ({"scope": "atproto repo:not a nsid"}, "invalid_scope"),
    ({"scope": "atproto rpc:sh.tangled.repo.create?aud=not-a-did"}, "invalid_scope"),
    ({"response_mode": "form_post"}, "invalid_request"),
])
async def test_par_rejects(client, registered, overrides, error):
    await par_rejected(client, registered(), error, **overrides)


@pytest.mark.parametrize("overrides", [
    {"scope": "atproto repo:org.example.thing"},
    {"scope": "atproto repo:sh.tangled.repo rpc:sh.tangled.repo.create?aud=* "
              "rpc:sh.tangled.repo.merge?aud=did:web:knot.rook.host blob:*/*"},
    {"response_mode": "query"},
    {"response_mode": None},
    {"display": "page"},
])
async def test_par_accepts(client, registered, overrides):
    await do_par(client, registered(), **overrides)


async def test_fragment_response_mode_and_prompt_create(client, enroll, registered):
    """@atproto/oauth-client-browser asks for response_mode=fragment by default."""
    from urllib.parse import parse_qs
    rook = await enroll()
    client_id = registered()
    par = await do_par(client, client_id, response_mode="fragment", prompt="create")
    response = await client.get(par.authorize_path(), headers=consent_headers(rook.agent))
    assert response.status == 302, response.text
    base, _, fragment = response.headers["location"].partition("#")
    assert base == "http://127.0.0.1/callback"
    params = {key: values[0] for key, values in parse_qs(fragment).items()}
    assert params["code"] and params["state"] == par.state and params["iss"] == ORIGIN
    assert token_success(await exchange_code(client, par, params["code"]))["sub"]


async def test_par_errors_say_what_is_wrong(client, registered):
    form, _ = par_form(registered(), response_mode="form_post")
    response = await post_with_nonce(client, "/oauth/par", form, EcKey())
    assert response.json() == {"error": "invalid_request", "error_description": "response_mode must be query or fragment"}


async def test_par_accepts_loopback_port_variance(client, registered):
    await do_par(client, registered(redirect_uris=["http://127.0.0.1/callback"]), "http://127.0.0.1:49152/callback")


async def test_rook_cli_client_metadata_round_trips_through_par(client, env):
    client_id = "https://rook.host/client-metadata.json"
    scope = ("atproto transition:generic repo:sh.tangled.repo repo:sh.tangled.repo.pull blob:*/* "
             "rpc:sh.tangled.repo.create?aud=did:web:knot.rook.host rpc:sh.tangled.git.receivePack?aud=did:web:knot.rook.host")
    serve_metadata(env, client_id, {
        "client_id": client_id, "client_name": "rook cli", "application_type": "native",
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        "redirect_uris": ["http://127.0.0.1/callback"], "scope": scope, "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": True, "client_uri": "https://rook.host",
    })
    par = await do_par(client, client_id, "http://127.0.0.1:8976/callback", scope=scope)
    stored = await store.get_par_request(env.db, par.request_uri)
    assert stored["scope"] == scope


# Client authentication

def _assertion(key: EcKey, client_id: str, aud: str) -> str:
    now = int(time.time())
    return key.jwt({"alg": "ES256", "kid": "client-key"}, {
        "iss": client_id, "sub": client_id, "aud": aud, "exp": now + 300, "iat": now, "jti": unique("jti"),
    })


async def test_valid_private_key_jwt_assertion(client, env):
    client_id, key = new_client_id("private-key"), EcKey()
    serve_metadata(env, client_id, client_metadata(
        client_id, token_endpoint_auth_method="private_key_jwt", token_endpoint_auth_signing_alg="ES256",
        jwks={"keys": [dict(key.jwk, kid="client-key")]}))
    await do_par(client, client_id, client_assertion_type=CLIENT_ASSERTION_TYPE,
                 client_assertion=_assertion(key, client_id, ORIGIN))


async def test_private_key_jwt_assertion_with_bad_audience(client, env):
    client_id, key = new_client_id("bad-aud"), EcKey()
    serve_metadata(env, client_id, client_metadata(
        client_id, token_endpoint_auth_method="private_key_jwt", token_endpoint_auth_signing_alg="ES256",
        jwks={"keys": [dict(key.jwk, kid="client-key")]}))
    await par_rejected(client, client_id, "invalid_client", 401, client_assertion_type=CLIENT_ASSERTION_TYPE,
                       client_assertion=_assertion(key, client_id, "https://wrong.example"))


async def test_metadata_client_id_mismatch_for_none_clients(client, env):
    client_id = new_client_id("mismatch")
    serve_metadata(env, client_id, client_metadata("https://other.example/client.json"))
    await par_rejected(client, client_id, "invalid_client", 401)


# Authorize rejections

async def test_unknown_request_uri_without_redirect(client):
    response = await client.get(AUTHORIZE_PATH, params={"request_uri": "urn:missing", "client_id": "https://client.example/missing.json"})
    assert response.status == 400
    assert "location" not in response.headers


async def test_expired_request_uri_without_redirect(client, env, registered):
    par = await do_par(client, registered())
    await env.db.run("UPDATE oauth_par_requests SET exp = 0 WHERE request_uri = ?", par.request_uri)
    response = await client.get(par.authorize_path())
    assert response.status == 400
    assert "location" not in response.headers


async def test_client_id_mismatch_without_redirect(client, registered):
    par = await do_par(client, registered())
    response = await client.get(AUTHORIZE_PATH, params={"request_uri": par.request_uri, "client_id": "https://other.example/client.json"})
    assert response.status == 400
    assert response.json()["error"] == "invalid_request"
    assert "location" not in response.headers


async def test_stale_tos_consent_token(client, enroll, registered):
    rook = await enroll()
    par = await do_par(client, registered())
    response = await client.get(par.authorize_path(), headers=consent_headers(rook.agent, rook.agent.make_access_token("wrong tos text")))
    assert response.status == 401
    assert response.json()["error"] == "tos_changed"


async def test_consent_proof_for_a_key_with_no_account(client, registered):
    par = await do_par(client, registered())
    stranger = Agent(ORIGIN, await tos_text(client))
    response = await client.get(par.authorize_path(), headers=consent_headers(stranger))
    assert response.status == 401
    assert response.json()["error"] == "AccountNotFound"


async def test_deactivated_account_gets_no_code(client, env, enroll, registered):
    rook = await enroll()
    await env.db.run("UPDATE accounts SET active = 0 WHERE did = ?", rook.did)
    redirect_uri = f"http://127.0.0.1/callback?case={unique('deactivated')}"
    par = await do_par(client, registered("deactivated", [redirect_uri]), redirect_uri)
    response = await client.get(par.authorize_path(), headers=consent_headers(rook.agent))
    assert response.status == 401
    assert response.json()["error"] == "AccountNotFound"
    assert await code_row_for_redirect(env, redirect_uri) is None


# Consent proof binding

async def test_consent_dpop_htu_with_the_query_is_rejected(client, enroll, registered):
    rook = await enroll()
    par = await do_par(client, registered())
    response = await client.get(par.authorize_path(), headers=consent_headers(rook.agent, htu=ORIGIN + par.authorize_path()))
    assert response.status == 401


async def test_consent_dpop_with_wrong_ath_is_rejected(client, enroll, registered):
    rook = await enroll()
    par = await do_par(client, registered())
    token = rook.agent.make_access_token()
    response = await client.get(par.authorize_path(), headers={
        "authorization": f"DPoP {token}",
        "dpop": rook.agent.dpop("GET", AUTHORIZE_PATH, token + "-tampered"),
    })
    assert response.status == 401
