# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The commons variant: invite-gated enrollment, invite minting and quotas,
Cloudflare Access on admin routes, and operator account takedown."""

import asyncio
import hashlib
import json
import logging
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from agent import Agent, _int_b64, _jwt
from conftest import ORIGIN, signup, tos_text, unique
from fakes import Client, Env
from rookery import directory
from rookery.encoding import b64url_encode
from rookery.net import HttpResponse
from rookery.oauth import store

TEAM_DOMAIN = "test.cloudflareaccess.com"
ACCESS_AUD = "test-access-aud"
CANONICAL_TOS_SHA256_HEX = "ae7ddbf25eeaa781e61d0cb0b5a4a2fdbf345f73c4892d5023bf065e30cdd2b4"
CREATE = "/xrpc/com.atproto.repo.createRecord"


class Access:
    """A Cloudflare Access signing key, its JWKS served to the env, and assertions."""

    def __init__(self, env: Env):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = self.key.public_key().public_numbers()
        self.kid = unique("access-kid")
        jwk = {"kid": self.kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": _int_b64(numbers.n), "e": _int_b64(numbers.e)}
        body = json.dumps({"keys": [jwk], "public_cert": "", "public_certs": []}).encode()
        env.http.routes[f"https://{TEAM_DOMAIN}/cdn-cgi/access/certs"] = lambda *_: HttpResponse(200, body)

    def assertion(self, **overrides) -> str:
        now = int(time.time())
        return _jwt({"alg": "RS256", "kid": self.kid}, dict({
            "iss": f"https://{TEAM_DOMAIN}",
            "aud": [ACCESS_AUD],
            "exp": now + 300,
            "iat": now,
            "sub": "access-test-sub",
            "email": "operator@example.com",
            "identity_nonce": unique("nonce"),
        }, **overrides), self.key)


@pytest.fixture
def env():
    return Env(ROOKERY_VARIANT="commons", CF_ACCESS_TEAM_DOMAIN=TEAM_DOMAIN, CF_ACCESS_AUD=ACCESS_AUD)


@pytest.fixture
def access(env):
    return Access(env)


@pytest.fixture
def admin(client, access):
    async def admin_request(method: str, path: str, claims: dict | None = None, **kwargs):
        headers = dict(kwargs.pop("headers", {}), **{"Cf-Access-Jwt-Assertion": access.assertion(**(claims or {}))})
        return await client.request(method, path, headers=headers, **kwargs)
    return admin_request


def entry_ref(token: str) -> str:
    return f"{ORIGIN}/roost#{token}"


def plc_calls(env) -> int:
    return sum(1 for call in env.http.calls if call["url"].startswith(env.ROOKERY_PLC_URL))


async def insert_invite(env, token: str) -> None:
    await directory.init_directory(env.db)
    await env.db.run("INSERT INTO invites (token) VALUES (?)", token)


async def get_invite(env, token: str):
    return await env.db.first(
        "SELECT token, minted_by, minted_at, spent_by_did, spent_at FROM invites WHERE token = ?", token)


async def account_exists(env, did: str) -> bool:
    return await env.db.first("SELECT 1 FROM accounts WHERE did = ? LIMIT 1", did) is not None


async def no_account(env, name: str) -> bool:
    return await env.db.first("SELECT 1 FROM accounts WHERE handle = ? LIMIT 1", name + ".rookery.test") is None


@pytest.fixture
def invited(env, enroll):
    """Enroll a rook with a freshly inserted invite."""
    async def enroll_invited(prefix: str = "rook"):
        token = unique(f"{prefix}-invite")
        await insert_invite(env, token)
        rook = await enroll(unique(prefix), ref=entry_ref(token))
        rook.invite_token = token
        return rook
    return enroll_invited


async def publish(rook, collection: str = "app.bsky.feed.post", rkey: str | None = None) -> dict:
    response = await rook.create(collection, {"text": unique("post"), "createdAt": "2026-01-01T00:00:00Z"}, rkey)
    assert response.status == 200, response.text
    return response.json()


async def mint(rook):
    return await rook.post("/api/invites")


async def takedown(admin, rook, **claims):
    return await admin("DELETE", f"/admin/accounts/{rook.did}", claims, json_body={"confirm": rook.handle})


# ToS and metadata

async def test_tos_is_the_canonical_bytes(client):
    response = await client.get("/tos")
    assert response.status == 200
    assert response.headers["content-type"] == "text/markdown; charset=utf-8"
    assert response.body[0] != 0xEF
    text = response.text
    assert "\r" not in text
    assert text.startswith("**rook.host — the rules**")
    assert text.endswith("your own rookery is always your fallback.\n")
    assert "**handle.**" in text
    assert hashlib.sha256(response.body).hexdigest() == CANONICAL_TOS_SHA256_HEX


async def test_serves_the_rook_cli_client_metadata(client):
    response = await client.get("/client-metadata.json")
    assert response.status == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {
        "client_id": f"{ORIGIN}/client-metadata.json",
        "client_name": "rook cli",
        "application_type": "native",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "redirect_uris": ["http://127.0.0.1/callback"],
        "scope": "atproto",
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": True,
        "client_uri": ORIGIN,
    }


# Invite-gated enrollment

async def test_ref_is_required_before_handle_policy(client, env):
    name = unique("missing-ref")
    response, _ = await signup(client, name)
    assert response.status == 403
    assert response.json() == {"error": "InviteRequired", "message": "A valid invite ref is required for enrollment."}
    assert plc_calls(env) == 0
    assert await no_account(env, name)
    ordering, _ = await signup(client, "ab")
    assert ordering.status == 403 and ordering.json()["error"] == "InviteRequired"


@pytest.mark.parametrize("ref", [f"{ORIGIN}/roost#", "not a url"])
async def test_empty_fragment_and_unparseable_refs(client, env, ref):
    response, _ = await signup(client, unique("bad-ref"), ref=ref)
    assert response.status == 403 and response.json()["error"] == "InviteRequired"
    assert plc_calls(env) == 0


async def test_unknown_and_spent_invites_are_rejected_without_plc_writes(client, env):
    spent = unique("spent-token")
    await insert_invite(env, spent)
    assert await directory.spend_invite_pending(env.db, spent)

    name = unique("unknown-token")
    response, _ = await signup(client, name, ref=entry_ref(unique("missing-token")))
    assert response.status == 403
    assert response.json() == {"error": "InviteInvalid", "message": "Invite is invalid or already spent."}
    assert await no_account(env, name)

    name = unique("spent")
    response, _ = await signup(client, name, ref=entry_ref(spent))
    assert response.status == 403 and response.json()["error"] == "InviteInvalid"
    assert await no_account(env, name)
    assert plc_calls(env) == 0


async def test_enrolls_with_an_unspent_invite_and_spends_it(client, env):
    name, token = unique("happy"), unique("happy-token")
    await insert_invite(env, token)
    response, _ = await signup(client, name, ref=entry_ref(token))
    assert response.status == 200
    body = response.json()
    assert body["handle"] == name + ".rookery.test"
    assert body["did"].startswith("did:plc:")
    assert body["token_type"] == "DPoP"
    invite = await get_invite(env, token)
    assert invite["spent_by_did"] == body["did"] and invite["spent_at"]
    assert await account_exists(env, body["did"])
    assert plc_calls(env) == 1


async def test_only_one_concurrent_signup_spends_an_invite(client, env):
    token = unique("concurrent-token")
    await insert_invite(env, token)
    results = await asyncio.gather(*(signup(client, unique(n), ref=entry_ref(token)) for n in ("con-a", "con-b")))
    responses = [response for response, _ in results]
    successes = [r for r in responses if r.status == 200]
    failures = [r for r in responses if r.status != 200]
    assert len(successes) == 1 and len(failures) == 1
    assert failures[0].status == 403 and failures[0].json()["error"] == "InviteInvalid"
    assert plc_calls(env) == 1
    did = successes[0].json()["did"]
    assert (await get_invite(env, token))["spent_by_did"] == did
    assert await account_exists(env, did)


async def test_invite_is_unspent_when_plc_creation_fails(client, env):
    name, token = unique("plc-fail"), unique("plc-fail-token")
    await insert_invite(env, token)
    env.plc.reject = 500
    response, _ = await signup(client, name, ref=entry_ref(token))
    assert response.status >= 500
    assert await no_account(env, name)
    invite = await get_invite(env, token)
    assert invite["spent_by_did"] is None and invite["spent_at"] is None
    assert plc_calls(env) == 1


async def test_invite_is_unspent_when_the_account_insert_loses_a_race(client, env):
    name, token = unique("unique-race"), unique("unique-race-token")
    await insert_invite(env, token)
    plc = env.plc

    async def racing(method, url, headers, body):
        await directory.insert_account(env.db, f"did:plc:{unique('race')}", name + ".rookery.test", unique("race-do"))
        return plc(method, url, headers, body)
    env.http.routes[env.ROOKERY_PLC_URL] = racing

    response, _ = await signup(client, name, ref=entry_ref(token))
    assert response.status == 409
    assert response.json() == {"error": "HandleTaken", "message": "Handle is already taken. Choose another name."}
    invite = await get_invite(env, token)
    assert invite["spent_by_did"] is None and invite["spent_at"] is None
    assert plc_calls(env) == 1


async def test_describe_server_and_welcome_text(client):
    assert (await client.get("/xrpc/com.atproto.server.describeServer")).json()["inviteCodeRequired"] is True
    welcome = await client.get("/.well-known/welcome.md")
    assert welcome.status == 200
    for needle in ("WelcomeMat v1.1", "`ref`", "POST /api/invites", "DPoP", "lifetime-quota", '"url"', "MintLocked", "QuotaExceeded"):
        assert needle in welcome.text


async def test_roost_redirects_to_the_invite_landing(client):
    response = await client.get("/roost")
    assert response.status == 302
    assert response.headers["location"] == "/invite"
    assert "Continue to rookery" in response.text


# Minting and quotas

async def test_default_quota_of_three_and_minted_invites_spend(client, env, invited):
    rook = await invited("default-quota")
    await publish(rook)
    first = await mint(rook)
    assert first.status == 200
    body = first.json()
    assert sorted(body) == ["remaining", "token", "url"]
    assert body["remaining"] == 2
    assert body["url"] == f"{ORIGIN}/roost#{body['token']}"

    response, _ = await signup(client, unique("mint-spend"), ref=body["url"])
    assert response.status == 200
    assert (await get_invite(env, body["token"]))["spent_by_did"] == response.json()["did"]

    assert (await mint(rook)).json()["remaining"] == 1
    assert (await mint(rook)).json()["remaining"] == 0
    fourth = await mint(rook)
    assert fourth.status == 403 and fourth.json()["error"] == "QuotaExceeded"


async def test_proof_of_life_is_checked_before_quota(env, invited):
    rook = await invited("locked")
    await directory.set_invite_quota(env.db, rook.did, 0)
    locked = await mint(rook)
    assert locked.status == 403 and locked.json()["error"] == "MintLocked"
    await publish(rook)
    exceeded = await mint(rook)
    assert exceeded.status == 403 and exceeded.json()["error"] == "QuotaExceeded"


async def test_per_rook_quota_overrides(env, invited):
    rook = await invited("override-five")
    await publish(rook)
    await directory.set_invite_quota(env.db, rook.did, 5)
    for remaining in range(4, -1, -1):
        minted = await mint(rook)
        assert minted.status == 200 and minted.json()["remaining"] == remaining
    blocked = await mint(rook)
    assert blocked.status == 403 and blocked.json()["error"] == "QuotaExceeded"


async def test_org_operators_mint_unlimited_invites_through_access(client, env, admin):
    response = await admin("POST", "/admin/invites")
    assert response.status == 200
    body = response.json()
    assert sorted(body) == ["token", "url"]
    assert body["url"] == f"{ORIGIN}/roost#{body['token']}"
    assert (await get_invite(env, body["token"]))["minted_by"] == "org"
    signed_up, _ = await signup(client, unique("org-minted"), ref=body["url"])
    assert signed_up.status == 200
    assert (await get_invite(env, body["token"]))["spent_by_did"] == signed_up.json()["did"]


@pytest.mark.parametrize("claims,status", [
    ({}, 200),
    ({"aud": ["wrong-aud"]}, 403),
    ({"aud": ACCESS_AUD}, 200),
    ({"aud": "definitely-not-the-aud"}, 403),
    ({"aud": 42}, 403),
    ({"aud": [42]}, 403),
    ({"exp": int(time.time()) - 1}, 403),
])
async def test_access_jwt_claims_on_admin_routes(admin, claims, status):
    response = await admin("POST", "/admin/invites", claims)
    assert response.status == status, response.text
    if status == 403:
        assert response.json()["error"] == "AccessDenied"


async def test_access_jwt_missing_or_forged(client, access):
    missing = await client.post("/admin/invites")
    assert missing.status == 403 and missing.json()["error"] == "AccessDenied"
    head, payload, signature = access.assertion().split(".")
    forged = f"{head}.{payload}.{'B' if signature.startswith('A') else 'A'}{signature[1:]}"
    response = await client.post("/admin/invites", headers={"Cf-Access-Jwt-Assertion": forged})
    assert response.status == 403 and response.json()["error"] == "AccessDenied"


async def test_admin_quota_and_config_updates(admin, invited):
    for body in ({}, {"quota": -1}, {"quota": 1.5}, {"quota": "1"}):
        response = await admin("PUT", "/admin/quotas/did:plc:badquota", json_body=body)
        assert response.status == 400 and response.json()["error"] == "InvalidRequest", body
    quota = await admin("PUT", "/admin/quotas/did:plc:quota-route", json_body={"quota": 4})
    assert quota.status == 200
    assert quota.json() == {"did": "did:plc:quota-route", "quota": 4}

    for body in ({}, {"value": -1}, {"value": 1.5}, {"value": "1"}):
        response = await admin("PUT", "/admin/config/invite_quota_default", json_body=body)
        assert response.status == 400 and response.json()["error"] == "InvalidRequest", body
    config = await admin("PUT", "/admin/config/invite_quota_default", json_body={"value": 1})
    assert config.status == 200 and config.json() == {"value": 1}

    rook = await invited("default-one")
    await publish(rook)
    assert (await mint(rook)).json()["remaining"] == 0
    second = await mint(rook)
    assert second.status == 403 and second.json()["error"] == "QuotaExceeded"


async def test_invite_listing_order_clamp_cursor_and_spent_state(env, admin):
    prefix = unique("list")
    await directory.init_directory(env.db)
    insert = "INSERT INTO invites (token, minted_by, minted_at, spent_by_did, spent_at) VALUES (?, ?, ?, ?, ?)"
    await env.db.batch([
        (insert, [f"{prefix}-older", "org", "2099-01-01 00:00:00", None, None]),
        (insert, [f"{prefix}-newer", "did:plc:list", "2099-01-02 00:00:00", "did:plc:spent", "2099-01-03 00:00:00"]),
    ])
    first = await admin("GET", "/admin/invites?limit=1")
    assert first.status == 200
    body = first.json()
    assert len(body["records"]) == 1
    record = body["records"][0]
    assert (record["token"], record["minted_by"], record["spent_by_did"]) == (f"{prefix}-newer", "did:plc:list", "did:plc:spent")
    assert body["cursor"]

    second = await admin("GET", "/admin/invites", params={"limit": "1", "cursor": body["cursor"]})
    assert second.json()["records"][0]["token"] == f"{prefix}-older"

    empty = await admin("GET", "/admin/invites", params={"cursor": b64url_encode(b"0000-01-01 00:00:00 zzz")})
    assert empty.status == 200
    assert empty.json() == {"records": []}

    invalid = await admin("GET", "/admin/invites?cursor=not-base64url")
    assert invalid.status == 400 and invalid.json()["error"] == "InvalidRequest"

    await env.db.batch([
        ("INSERT INTO invites (token, minted_by, minted_at) VALUES (?, ?, ?)", [f"{prefix}-bulk-{i:03d}", "org", "2099-02-01 00:00:00"])
        for i in range(501)
    ])
    clamped = await admin("GET", "/admin/invites?limit=9999")
    assert len(clamped.json()["records"]) == 500


# Admin invite lifecycle

async def test_concurrent_cold_start_mints_are_structured_and_distinct(admin):
    responses = await asyncio.gather(*(admin("POST", "/admin/invites") for _ in range(6)))
    tokens = set()
    for response in responses:
        assert response.status == 200
        assert response.headers["content-type"].startswith("application/json")
        body = response.json()
        assert body["url"] == f"{ORIGIN}/roost#{body['token']}"
        tokens.add(body["token"])
    assert len(tokens) == len(responses)


async def test_re_mints_idempotently_per_key(env, admin):
    key = unique("idem")
    first = await admin("POST", "/admin/invites", headers={"Idempotency-Key": key})
    assert first.status == 200 and "idempotency-replayed" not in first.headers
    replay = await admin("POST", "/admin/invites", headers={"Idempotency-Key": key})
    assert replay.status == 200 and replay.headers["idempotency-replayed"] == "true"
    assert replay.json() == first.json()
    row = await env.db.first("SELECT COUNT(*) AS count FROM invites WHERE idempotency_key = ?", key)
    assert row["count"] == 1

    other = await admin("POST", "/admin/invites", headers={"Idempotency-Key": unique("idem-other")})
    assert other.json()["token"] != first.json()["token"]
    a, b = await admin("POST", "/admin/invites"), await admin("POST", "/admin/invites")
    assert a.json()["token"] != b.json()["token"]

    blank = await admin("POST", "/admin/invites", headers={"Idempotency-Key": "   "})
    assert blank.status == 400 and blank.json()["error"] == "InvalidRequest"


async def test_revokes_unspent_invites_and_rejects_spent_or_unknown(env, admin):
    token = (await admin("POST", "/admin/invites")).json()["token"]
    assert await get_invite(env, token)
    revoke = await admin("DELETE", f"/admin/invites/{token}")
    assert revoke.status == 200 and revoke.json() == {"token": token, "revoked": True}
    assert await get_invite(env, token) is None

    again = await admin("DELETE", f"/admin/invites/{token}")
    assert again.status == 404 and again.json()["error"] == "InviteNotFound"

    spent = unique("revoke-spent")
    await env.db.run(
        "INSERT INTO invites (token, minted_by, spent_by_did, spent_at) VALUES (?, 'org', ?, datetime('now'))", spent, "did:plc:spender")
    response = await admin("DELETE", f"/admin/invites/{spent}")
    assert response.status == 409 and response.json()["error"] == "InviteSpent"
    assert await get_invite(env, spent)


async def test_listing_filters_by_state(env, admin):
    prefix = unique("state")
    await directory.init_directory(env.db)
    insert = "INSERT INTO invites (token, minted_by, minted_at, spent_by_did, spent_at) VALUES (?, 'org', ?, ?, ?)"
    await env.db.batch([
        (insert, [f"{prefix}-unspent", "2099-06-01 00:00:00", None, None]),
        (insert, [f"{prefix}-spent", "2099-06-02 00:00:00", "did:plc:spent", "2099-06-03 00:00:00"]),
        (insert, [f"{prefix}-pending", "2099-06-04 00:00:00", "pending", "2099-06-05 00:00:00"]),
    ])
    unspent = (await admin("GET", "/admin/invites?state=unspent&limit=500")).json()["records"]
    assert [r["token"] for r in unspent] == [f"{prefix}-unspent"]
    assert all(r["spent_by_did"] is None for r in unspent)
    spent = {r["token"] for r in (await admin("GET", "/admin/invites?state=spent&limit=500")).json()["records"]}
    assert spent == {f"{prefix}-spent", f"{prefix}-pending"}
    invalid = await admin("GET", "/admin/invites?state=bogus")
    assert invalid.status == 400 and invalid.json()["error"] == "InvalidRequest"


# Operator account takedown

async def test_takedown_removes_account_records_blobs_and_audits(client, env, admin, invited):
    rook = await invited("takedown-full")
    post = await publish(rook, "app.bsky.feed.post", "primary-post")
    await publish(rook, "com.example.note", "primary-note")
    uploaded = await rook.client.post("/xrpc/com.atproto.repo.uploadBlob", body=b"remove me", headers=dict(
        rook.agent.auth_headers("POST", "/xrpc/com.atproto.repo.uploadBlob"), **{"content-type": "text/plain"}))
    blob_cid = uploaded.json()["blob"]["ref"]["$link"]

    response = await takedown(admin, rook)
    assert response.status == 200
    assert response.json() == {
        "did": rook.did, "handle": rook.handle, "recordsDeleted": 2, "blobsDeleted": 1,
        "collections": ["app.bsky.feed.post", "com.example.note"],
    }
    assert (await client.get("/xrpc/com.atproto.identity.resolveHandle", params={"handle": rook.handle})).status == 404
    assert (await client.get("/.well-known/atproto-did", headers={"host": rook.handle})).status == 404
    record = await client.get("/xrpc/com.atproto.repo.getRecord", params={
        "repo": rook.did, "collection": "app.bsky.feed.post", "rkey": post["uri"].rsplit("/", 1)[1]})
    assert record.status == 404 and record.json()["error"] == "RepoNotFound"
    repo = await client.get("/xrpc/com.atproto.sync.getRepo", params={"did": rook.did})
    assert repo.status == 404 and repo.json()["error"] == "RepoNotFound"
    assert f"{rook.did}/{blob_cid}" not in env.blobs.objects
    assert not await account_exists(env, rook.did)

    audit = await env.db.first(
        "SELECT did, handle, actor, records_deleted, blobs_deleted, collections, taken_down_at FROM takedowns WHERE did = ?", rook.did)
    assert audit["actor"] == "operator@example.com"
    assert (audit["records_deleted"], audit["blobs_deleted"]) == (2, 1)
    assert audit["collections"] == json.dumps(["app.bsky.feed.post", "com.example.note"], separators=(",", ":"))
    assert audit["taken_down_at"]


async def test_takedown_purges_many_r2_pages_and_spares_other_dids(env, admin, invited):
    rook = await invited("takedown-r2-pages")
    for index in range(1001):
        env.blobs.objects[f"{rook.did}/blob-{index:04d}"] = (b"blob", "text/plain")
    foreign = f"did:plc:{unique('foreign')}/keep"
    env.blobs.objects[foreign] = (b"keep", "text/plain")
    response = await takedown(admin, rook)
    assert response.status == 200 and response.json()["blobsDeleted"] == 1001
    assert not [key for key in env.blobs.objects if key.startswith(f"{rook.did}/")]
    assert foreign in env.blobs.objects


async def test_takedown_emits_chunked_delete_commits_then_the_account_frame(env, admin, invited):
    rook = await invited("takedown-firehose")
    await env.account_do(await _do_id(env, rook.did)).account.apply_writes(writes=[
        {"$type": "com.atproto.repo.applyWrites#create", "collection": "app.bsky.feed.post",
         "rkey": f"r{index:03d}", "record": {"text": f"post {index}"}}
        for index in range(201)
    ])
    socket = env.sequencer.connect()
    response = await takedown(admin, rook)
    assert response.status == 200
    assert {k: response.json()[k] for k in ("recordsDeleted", "collections")} == {
        "recordsDeleted": 201, "collections": ["app.bsky.feed.post"]}
    frames = socket.events()
    assert [header["t"] for header, _ in frames] == ["#commit", "#commit", "#account"]
    ops = frames[0][1]["ops"] + frames[1][1]["ops"]
    assert (len(frames[0][1]["ops"]), len(frames[1][1]["ops"])) == (200, 1)
    assert [op["path"] for op in ops] == [f"app.bsky.feed.post/r{index:03d}" for index in range(201)]
    assert all(op["action"] == "delete" and op["cid"] is None for op in ops)
    assert {k: frames[2][1][k] for k in ("did", "active", "status")} == {"did": rook.did, "active": False, "status": "deleted"}


async def _do_id(env, did: str) -> str:
    return (await env.db.first("SELECT do_id FROM accounts WHERE did = ?", did))["do_id"]


async def test_takedown_of_an_empty_account_emits_only_the_account_frame(env, admin, invited):
    rook = await invited("takedown-empty")
    do_id = await _do_id(env, rook.did)
    socket = env.sequencer.connect()
    response = await takedown(admin, rook)
    assert response.status == 200
    assert {k: response.json()[k] for k in ("recordsDeleted", "blobsDeleted", "collections")} == {
        "recordsDeleted": 0, "blobsDeleted": 0, "collections": []}
    frames = socket.events()
    assert [header["t"] for header, _ in frames] == ["#account"]
    assert frames[0][1]["status"] == "deleted" and frames[0][1]["active"] is False
    assert await env.account_do(do_id).account.get_state() is None


async def test_takedown_validates_before_changing_state(client, env, admin, invited):
    rook = await invited("takedown-confirm")
    await publish(rook, "app.bsky.feed.post", "still-here")
    events_before = len(env.sequencer.rows())
    path = f"/admin/accounts/{rook.did}"

    for body in ({}, {"confirm": rook.handle + "-wrong"}):
        response = await admin("DELETE", path, json_body=body)
        assert response.status == 400 and response.json()["error"] == "ConfirmMismatch"
    unknown = await admin("DELETE", "/admin/accounts/did:plc:missing", json_body={"confirm": "missing.rookery.test"})
    assert unknown.status == 404 and unknown.json()["error"] == "AccountNotFound"
    malformed = await admin("DELETE", path, body=b"not-json", headers={"content-type": "application/json"})
    assert malformed.status == 400 and malformed.json()["error"] == "InvalidRequest"

    assert (await env.db.first("SELECT active FROM accounts WHERE did = ?", rook.did))["active"] == 1
    got = await client.get("/xrpc/com.atproto.repo.getRecord", params={"repo": rook.did, "collection": "app.bsky.feed.post", "rkey": "still-here"})
    assert got.status == 200
    assert await env.db.first("SELECT 1 FROM takedowns WHERE did = ?", rook.did) is None
    assert len(env.sequencer.rows()) == events_before


async def test_takedown_retry_of_a_wiped_account(env, admin, invited):
    rook = await invited("takedown-retry")
    account = env.account_do(await _do_id(env, rook.did)).account
    socket = env.sequencer.connect()
    assert await account.takedown(did=rook.did) == {"recordsDeleted": 0, "blobsDeleted": 0, "collections": []}
    assert (await env.db.first("SELECT active FROM accounts WHERE did = ?", rook.did))["active"] == 1
    await directory.deactivate_account(env.db, rook.did)
    late = f"{rook.did}/late-after-wipe"
    env.blobs.objects[late] = (b"late", "text/plain")

    response = await takedown(admin, rook)
    assert response.status == 200
    assert {k: response.json()[k] for k in ("recordsDeleted", "blobsDeleted", "collections")} == {
        "recordsDeleted": 0, "blobsDeleted": 1, "collections": []}
    assert late not in env.blobs.objects
    assert not await account_exists(env, rook.did)
    assert (await env.db.first("SELECT COUNT(*) AS count FROM takedowns WHERE did = ?", rook.did))["count"] == 1
    frames = socket.events()
    assert [header["t"] for header, _ in frames] == ["#account", "#account"]
    assert all(body["did"] == rook.did and body["status"] == "deleted" and body["active"] is False for _, body in frames)


async def test_takedown_keeps_invites_and_removes_oauth_state_and_quota(env, admin, invited):
    rook = await invited("takedown-related")
    minted = unique("target-minted")
    await env.db.run("INSERT INTO invites (token, minted_by) VALUES (?, ?)", minted, rook.did)
    await directory.set_invite_quota(env.db, rook.did, 7)
    await store.init_oauth(env.db)
    suffix, now = unique("oauth"), int(time.time())
    common = {"client_id": "https://client.example", "scope": "atproto", "did": rook.did, "dpop_jkt": f"jkt-{suffix}", "exp": now + 300}
    await store.insert_code(env.db, dict(common, code_hash=f"code-{suffix}", redirect_uri="https://client.example/callback",
                                         code_challenge=f"challenge-{suffix}"), now)
    await store.insert_session(env.db, dict(common, session_id=f"session-{suffix}", refresh_token_hash=f"refresh-{suffix}"), now)
    await store.insert_token(env.db, dict(common, access_token_hash=f"access-{suffix}", session_id=f"session-{suffix}"), now)

    assert (await takedown(admin, rook)).status == 200
    assert (await get_invite(env, rook.invite_token))["spent_by_did"] == rook.did
    kept = await get_invite(env, minted)
    assert kept["minted_by"] == rook.did and kept["spent_by_did"] is None
    for table in ("oauth_codes", "oauth_sessions", "oauth_tokens", "invite_quotas"):
        assert await env.db.first(f"SELECT 1 FROM {table} WHERE did = ? LIMIT 1", rook.did) is None, table


async def test_audit_actor_falls_back_to_common_name_then_sub(env, admin, invited):
    service = await invited("takedown-service-actor")
    assert (await takedown(admin, service, email="", common_name="service-token.access", sub="")).status == 200
    by_sub = await invited("takedown-sub-actor")
    assert (await takedown(admin, by_sub, email="", common_name="", sub=4242)).status == 200
    rows = await env.db.all("SELECT did, actor FROM takedowns WHERE did IN (?, ?)", service.did, by_sub.did)
    assert {row["did"]: row["actor"] for row in rows} == {service.did: "service-token.access", by_sub.did: "4242"}


# Security alert webhook

HUB = "https://hub.test/alerts"


def hub_env():
    return Env(ROOKERY_VARIANT="commons", CF_ACCESS_TEAM_DOMAIN=TEAM_DOMAIN, CF_ACCESS_AUD=ACCESS_AUD,
               HUB_WEBHOOK_URL=HUB, HUB_WEBHOOK_SECRET="test-hub-secret")


@pytest.mark.parametrize("hub", ["ok", "reject", "500"])
async def test_takedown_alert_delivery(hub, caplog):
    env = hub_env()
    client = Client(env)
    access = Access(env)
    received = []

    def handler(method, url, headers, body):
        received.append({"url": url, "method": method, "headers": headers, "body": json.loads(body)})
        if hub == "reject":
            raise ConnectionError("test webhook rejected")
        return HttpResponse(200 if hub == "ok" else 500, b"" if hub == "ok" else b"hub unavailable")
    env.http.routes[HUB] = handler

    token = unique("alert-invite")
    await insert_invite(env, token)
    response, agent = await signup(client, unique("takedown-alert"), ref=entry_ref(token))
    rook_did, handle = response.json()["did"], response.json()["handle"]
    created = await client.post(CREATE, json_body={"repo": rook_did, "collection": "app.bsky.feed.post", "record": {"text": "x"}},
                                headers=agent.auth_headers("POST", CREATE))
    assert created.status == 200

    with caplog.at_level(logging.ERROR):
        result = await client.delete(f"/admin/accounts/{rook_did}", json_body={"confirm": handle},
                                     headers={"Cf-Access-Jwt-Assertion": access.assertion()})
    assert result.status == 200
    summary = result.json()
    assert len(received) == 1
    request = received[0]
    assert request["url"] == HUB and request["method"] == "POST"
    assert request["headers"]["X-Hub-Secret"] == "test-hub-secret"
    assert request["headers"]["Content-Type"] == "application/json"
    body = request["body"]
    assert body == {
        "office": "cso", "ts": body["ts"], "type": "account_takedown", "tier": "T4", "actor": "operator@example.com",
        "did": rook_did, "handle": handle, "records_deleted": summary["recordsDeleted"],
        "blobs_deleted": summary["blobsDeleted"], "collections": summary["collections"],
    }
    assert body["ts"].endswith("Z") and len(body["ts"]) == len("2026-01-01T00:00:00.000Z")
    assert not await account_exists(env, rook_did)
    assert (await env.db.first("SELECT actor FROM takedowns WHERE did = ?", rook_did))["actor"] == "operator@example.com"
    failures = [r.getMessage() for r in caplog.records if "takedown security alert delivery failed" in r.getMessage()]
    if hub == "ok":
        assert failures == []
    else:
        assert len(failures) == 1 and rook_did in failures[0]
        assert ("test webhook rejected" if hub == "reject" else "500 hub unavailable") in failures[0]


async def test_takedown_does_not_call_the_hub_when_unconfigured(env, admin, invited):
    env.HUB_WEBHOOK_SECRET = "test-hub-secret"
    rook = await invited("takedown-alert-disabled")
    assert (await takedown(admin, rook)).status == 200
    assert not [call for call in env.http.calls if call["url"].startswith("https://hub.test/")]


async def test_admin_routes_404_when_access_is_unconfigured():
    client = Client(Env(ROOKERY_VARIANT="commons"))
    for method, path, body in (
        ("GET", "/admin/invites", None),
        ("POST", "/admin/invites", None),
        ("PUT", "/admin/quotas/did:plc:unset", {"quota": 1}),
        ("PUT", "/admin/config/invite_quota_default", {"value": 1}),
        ("DELETE", "/admin/invites/some-token", None),
        ("DELETE", "/admin/accounts/did:plc:unset", {"confirm": "unset.rookery.test"}),
    ):
        assert (await client.request(method, path, json_body=body)).status == 404, (method, path)
