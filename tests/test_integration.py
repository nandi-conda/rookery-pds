# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""End-to-end flows through the app: enrollment, writes, identity, blobs."""

import json

from agent import Agent, _jwt
from conftest import ORIGIN, signup, tos_text, unique
from rookery import directory
from rookery.encoding import sha256_b64url
from rookery.net import HttpResponse

CREATE = "/xrpc/com.atproto.repo.createRecord"


def event_types(env) -> list[str]:
    return [row["event_type"] for row in env.sequencer.rows()]


async def test_full_lifecycle_from_signup_through_firehose(client, env, enroll):
    rook = await enroll()
    assert rook.did.startswith("did:plc:")
    response = await rook.create("com.example.test", {"text": "hello", "createdAt": "2026-01-01T00:00:00Z"}, "post1")
    assert response.status == 200
    got = await client.get("/xrpc/com.atproto.repo.getRecord", params={"repo": rook.did, "collection": "com.example.test", "rkey": "post1"})
    assert got.status == 200 and got.json()["value"]["text"] == "hello"
    exported = await client.get("/xrpc/com.atproto.sync.getRepo", params={"did": rook.did})
    assert exported.status == 200
    assert exported.headers["content-type"] == "application/vnd.ipld.car"
    assert len(exported.body) > 0
    assert event_types(env) == ["identity", "account", "commit"]


async def test_multi_agent_writes_and_reads_are_isolated(client, enroll):
    a, b = await enroll(), await enroll()
    assert (await a.create("com.example.test", {"text": "from agent a"}, "a-post")).status == 200
    assert (await b.create("com.example.test", {"text": "from agent b"}, "b-post")).status == 200
    for rook, rkey, text in ((a, "a-post", "from agent a"), (b, "b-post", "from agent b")):
        got = await client.get("/xrpc/com.atproto.repo.getRecord", params={"repo": rook.did, "collection": "com.example.test", "rkey": rkey})
        assert got.json()["value"]["text"] == text
        listed = (await client.get("/xrpc/com.atproto.repo.listRecords", params={"repo": rook.did, "collection": "com.example.test"})).json()
        assert len(listed["records"]) == 1
        assert listed["records"][0]["uri"] == f"at://{rook.did}/com.example.test/{rkey}"
        assert listed["records"][0]["value"]["text"] == text


async def test_resolves_signed_up_handle_to_the_same_did(client, enroll):
    rook = await enroll()
    response = await client.get("/xrpc/com.atproto.identity.resolveHandle", params={"handle": rook.handle})
    assert response.json() == {"did": rook.did}


async def test_update_handle_moves_account_to_new_handle(client, env, enroll):
    name = unique("rename")
    rook = await enroll(name)
    path = "/xrpc/com.atproto.identity.updateHandle"
    assert (await rook.post(path, {"handle": "someone.else.example"})).status == 400

    new_handle = f"{name}-new.rookery.test"
    before = len(env.plc.log[rook.did])
    response = await rook.post(path, {"handle": new_handle})
    assert response.status == 200, response.text
    log = env.plc.log[rook.did]
    assert len(log) == before + 1
    op = log[-1]["operation"]
    genesis = log[0]
    assert op["alsoKnownAs"] == [f"at://{new_handle}"]
    assert op["prev"] == genesis["cid"]
    assert op["rotationKeys"] == genesis["operation"]["rotationKeys"]
    assert op["services"] == genesis["operation"]["services"]
    assert op["sig"] != genesis["operation"]["sig"]

    assert (await client.get("/xrpc/com.atproto.identity.resolveHandle", params={"handle": new_handle})).json() == {"did": rook.did}
    assert (await client.get("/xrpc/com.atproto.identity.resolveHandle", params={"handle": rook.handle})).status == 404
    described = await client.get("/xrpc/com.atproto.repo.describeRepo", params={"repo": rook.did})
    assert described.json()["handle"] == new_handle
    assert (await rook.post(path, {"handle": new_handle})).status == 409
    assert event_types(env)[-1] == "identity"


async def test_update_handle_refuses_a_did_whose_rotation_key_is_not_ours(env, enroll):
    rook = await enroll()
    env.plc.log[rook.did][0]["operation"]["rotationKeys"] = ["did:key:zSomeoneElse"]
    response = await rook.post("/xrpc/com.atproto.identity.updateHandle", {"handle": unique("rotator") + ".rookery.test"})
    assert response.status == 500


# Handle acceptance policy

RESERVED = {"error": "HandleReserved", "message": "Handle is reserved. Choose a different name."}


async def test_lowercases_labels_before_policy_and_storage(client):
    reserved, _ = await signup(client, "Admin")
    assert reserved.status == 400 and reserved.json() == RESERVED
    accepted, _ = await signup(client, "MyAgent")
    assert accepted.status == 200 and accepted.json()["handle"] == "myagent.rookery.test"


async def test_reserves_one_and_two_character_labels(client):
    for label in ("a", "ab"):
        response, _ = await signup(client, label)
        assert response.status == 400 and response.json() == RESERVED


async def test_blocks_exact_blocklist_labels(client):
    for label in ("admin", "knot", "pds", "www", "solpbc", "rook", "swastika"):
        response, _ = await signup(client, label)
        assert response.status == 400 and response.json() == RESERVED, label


async def test_rejects_dotted_and_invalid_labels(client):
    dotted, _ = await signup(client, "admin.x")
    assert dotted.status == 400
    assert dotted.json() == {"error": "InvalidHandle", "message": "Invalid handle: submit a single name without dots."}
    invalid, _ = await signup(client, "a-")
    assert invalid.status == 400 and invalid.json()["error"] == "InvalidHandle"


async def test_applies_blocklist_before_availability(client, env):
    await directory.init_directory(env.db)
    await directory.insert_account(env.db, "did:plc:blocktest", "admin.rookery.test", "blocktest-do")
    response, _ = await signup(client, "admin")
    assert response.status == 400 and response.json() == RESERVED


async def test_enrollment_edge_cases(client, env, enroll):
    name = unique("duphandle")
    await enroll(name)
    plc_posts = len(env.plc.log)
    accounts = len(env.accounts)
    duplicate, _ = await signup(client, name)
    assert duplicate.status == 409
    assert duplicate.json() == {"error": "HandleTaken", "message": "Handle is already taken. Choose another name."}
    assert len(env.plc.log) == plc_posts and len(env.accounts) == accounts

    # One key may hold several accounts; the newest... any of them still enrolls.
    first = await enroll()
    second, _ = await signup(client, unique("dup-thumb"), agent=first.agent)
    assert second.status == 200 and second.json()["did"].startswith("did:plc:")

    missing = await client.post(CREATE, json_body={"repo": "did:plc:missing-auth", "collection": "com.example.test", "record": {}})
    assert missing.status == 401
    invalid = await client.post(CREATE, json_body={"repo": "did:plc:x", "collection": "com.example.test", "record": {}},
                                headers={"Authorization": "DPoP fake-token", "DPoP": "not-a-jwt"})
    assert invalid.status == 401


async def test_ignores_signup_ref_in_the_reference_variant(client):
    name = unique("ref-ignored")
    response, _ = await signup(client, name, ref="https://rookery.test/roost#unused-reference-token")
    assert response.status == 200 and response.json()["handle"] == f"{name}.rookery.test"


async def test_rejects_signup_without_dpop(client):
    agent = Agent(ORIGIN, await tos_text(client))
    response = await client.post("/api/signup", json_body=agent.signup_body(unique("no-dpop")))
    assert response.status == 401 and response.json()["error"] == "AuthRequired"


async def test_rejects_signup_with_bad_tos_signature(client):
    tos = await tos_text(client)
    agent = Agent(ORIGIN, tos)
    body = agent.signup_body(unique("bad-tos-sig"))
    agent.tos_text = tos + "\n"
    body["tos_signature"] = agent.tos_signature()
    response = await client.post("/api/signup", json_body=body, headers={"DPoP": agent.dpop("POST", "/api/signup")})
    assert response.status == 400 and response.json()["error"] == "InvalidSignature"


async def test_rejects_signup_with_wrong_tos_hash(client):
    agent = Agent(ORIGIN, await tos_text(client))
    body = agent.signup_body(unique("wrong-tos-hash"), access_token=agent.make_access_token("wrong tos text"))
    response = await client.post("/api/signup", json_body=body, headers={"DPoP": agent.dpop("POST", "/api/signup")})
    assert response.status == 400 and response.json()["error"] == "InvalidToken"


async def test_rejects_write_with_stale_tos_hash(enroll):
    rook = await enroll()
    rook.agent.access_token = rook.agent.make_access_token("wrong tos text")
    response = await rook.create("com.example.test", {"text": "stale"}, "stale-token")
    assert response.status == 401 and response.json()["error"] == "tos_changed"


async def test_round_trips_blobs(client, enroll):
    rook = await enroll()
    data = b"test blob data"
    path = "/xrpc/com.atproto.repo.uploadBlob"
    response = await client.post(path, body=data, headers=dict(
        rook.agent.auth_headers("POST", path), **{"content-type": "application/octet-stream", "content-length": str(len(data))},
    ))
    assert response.status == 200
    cid = response.json()["blob"]["ref"]["$link"]
    downloaded = await client.get("/xrpc/com.atproto.sync.getBlob", params={"did": rook.did, "cid": cid})
    assert downloaded.status == 200 and downloaded.body == data


async def test_accepts_lexicon_agnostic_collections(enroll):
    rook = await enroll()
    for collection in ("com.example.foo.bar", "app.bsky.feed.post", "xyz.custom.thing", "io.github.myapp.status"):
        response = await rook.create(collection, {"text": collection}, collection.split(".")[-1])
        assert response.status == 200, collection


async def test_rejects_signup_when_plc_rejects(client, env):
    env.plc.reject = 400
    response, _ = await signup(client, unique("plc-down"))
    assert response.status == 500
    assert response.json() == {"error": "InternalError", "message": "Internal server error."}
    assert await env.db.first("SELECT 1 AS x FROM accounts") is None


async def test_dpop_proof_must_name_the_public_host(client, enroll):
    rook = await enroll()
    headers = {
        "Authorization": f"DPoP {rook.agent.access_token}",
        "DPoP": rook.agent.dpop("POST", CREATE, rook.agent.access_token, htu=f"http://localhost:8787{CREATE}"),
    }
    response = await client.post(CREATE, json_body={"repo": rook.did, "collection": "com.example.x", "record": {}}, headers=headers)
    assert response.status == 401
    assert response.json() == {"error": "AuthFailed", "message": "invalid DPoP proof: htu does not match request URL"}
    # A request that reached another host still verifies against the public one.
    other = await client.request("POST", f"http://localhost:8787{CREATE}", json_body={"repo": rook.did, "collection": "com.example.x", "record": {}},
                                 headers=rook.agent.auth_headers("POST", CREATE))
    assert other.status == 200, other.text


async def test_proof_and_token_must_share_a_key(client, enroll):
    a, b = await enroll(), await enroll()
    headers = {"Authorization": f"DPoP {a.agent.access_token}", "DPoP": b.agent.dpop("POST", CREATE, a.agent.access_token)}
    response = await client.post(CREATE, json_body={"repo": a.did, "collection": "com.example.x", "record": {}}, headers=headers)
    assert response.status == 401
    assert response.json()["message"] == "invalid access token: cnf.jkt does not match DPoP key"


async def test_rejects_writes_to_another_accounts_repo(enroll):
    a, b = await enroll(), await enroll()
    response = await a.post(CREATE, {"repo": b.did, "collection": "com.example.x", "record": {}})
    assert response.status == 400
    assert response.json()["message"] == "Repo DID does not match authenticated account"


async def test_knot_member_sync_runs_after_signup(client, env):
    env.ROOKERY_KNOT_ADMIN_ADD_MEMBER_URL = "https://knot.example/admin/members"
    env.ROOKERY_KNOT_ADMIN_SECRET = "s3cret"
    seen = []
    env.http.routes["https://knot.example/"] = lambda method, url, headers, body: seen.append((url, headers, json.loads(body))) or HttpResponse(200)
    response, _ = await signup(client, unique("knot"))
    did = response.json()["did"]
    assert seen == [("https://knot.example/admin/members", {
        "authorization": "Basic YWRtaW46czNjcmV0", "Content-Type": "application/json",
    }, {"subject": did})]


async def test_relay_crawl_is_requested_once(client, env):
    env.ROOKERY_RELAY_HOSTS = "relay.one, relay.two"
    env.http.routes["https://relay."] = lambda *args: HttpResponse(200)
    await client.get("/")
    await client.get("/")
    crawled = [call["url"] for call in env.http.calls if "requestCrawl" in call["url"]]
    assert crawled == ["https://relay.one/xrpc/com.atproto.sync.requestCrawl", "https://relay.two/xrpc/com.atproto.sync.requestCrawl"]
    assert json.loads(env.http.calls[0]["body"]) == {"hostname": "rookery.test"}


async def test_access_token_with_wrong_audience_fails(client, enroll):
    rook = await enroll()
    token = _jwt({"typ": "wm+jwt", "alg": "RS256"}, {
        "tos_hash": sha256_b64url(rook.agent.tos_text), "aud": "https://elsewhere.example", "cnf": {"jkt": rook.agent.thumbprint},
    }, rook.agent.key)
    rook.agent.access_token = token
    response = await rook.create("com.example.x", {})
    assert response.status == 401
    assert response.json()["message"] == "invalid access token: aud does not match service origin"
