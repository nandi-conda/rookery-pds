# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Routing concerns: CORS, documents, variant gating, and the repo read/write routes."""

import pytest

from roost.car import read_car


async def test_cors_on_get(client):
    response = await client.get("/")
    assert response.status == 200
    assert response.headers["access-control-allow-origin"] == "*"


async def test_options_preflight(client):
    response = await client.request("OPTIONS", "/xrpc/com.atproto.repo.getRecord", headers={
        "origin": "https://example.com",
        "access-control-request-method": "GET",
    })
    assert response.status == 204
    assert response.headers["access-control-allow-origin"] == "*"
    assert "GET" in response.headers["access-control-allow-methods"]
    assert "POST" in response.headers["access-control-allow-methods"]
    assert "Authorization" in response.headers["access-control-allow-headers"]
    assert "DPoP" in response.headers["access-control-allow-headers"]
    for name in ("Atproto-Proxy", "Atproto-Accept-Labelers"):
        assert name in response.headers["access-control-allow-headers"]
    assert response.headers["access-control-max-age"] == "86400"


async def test_options_preflight_reflects_client_headers(client):
    # bsky.app sends X-Atproto-Session-Id on every PDS call.
    response = await client.request("OPTIONS", "/xrpc/app.bsky.actor.getProfile", headers={
        "origin": "https://bsky.app",
        "access-control-request-method": "GET",
        "access-control-request-headers": "atproto-accept-labelers,authorization,x-atproto-session-id",
    })
    assert response.status == 204
    assert "x-atproto-session-id" in response.headers["access-control-allow-headers"]


async def test_cors_on_post_errors(client):
    response = await client.post("/xrpc/com.atproto.repo.createRecord", json_body={})
    assert response.status == 401
    assert response.headers["access-control-allow-origin"] == "*"


async def test_serves_welcome_and_terms(client):
    welcome = await client.get("/.well-known/welcome.md")
    assert welcome.status == 200 and "WelcomeMat" in welcome.text
    tos = await client.get("/tos")
    assert tos.status == 200 and "Terms of Service" in tos.text


@pytest.mark.parametrize("method,path,body", [
    ("GET", "/roost", None),
    ("POST", "/api/invites", None),
    ("POST", "/admin/invites", None),
    ("GET", "/admin/invites", None),
    ("PUT", "/admin/quotas/did:plc:reference", {"quota": 1}),
    ("PUT", "/admin/config/invite_quota_default", {"value": 1}),
    ("DELETE", "/admin/accounts/did:plc:reference", {"confirm": "reference.rookery.test"}),
])
async def test_commons_routes_are_hidden_on_the_reference_variant(client, method, path, body):
    assert (await client.request(method, path, json_body=body)).status == 404


async def test_repo_read_and_sync_routes(client, enroll):
    rook = await enroll()
    assert (await rook.create("app.bsky.feed.post", {"text": "route post"}, "route-rkey")).status == 200

    got = await client.get("/xrpc/com.atproto.repo.getRecord", params={"repo": rook.handle, "collection": "app.bsky.feed.post", "rkey": "route-rkey"})
    assert got.status == 200
    assert got.json()["uri"] == f"at://{rook.did}/app.bsky.feed.post/route-rkey"
    assert got.json()["value"]["text"] == "route post"

    listed = await client.get("/xrpc/com.atproto.repo.listRecords", params={"repo": rook.handle, "collection": "app.bsky.feed.post"})
    assert listed.status == 200
    assert any(record["uri"].endswith("/route-rkey") for record in listed.json()["records"])

    described = await client.get("/xrpc/com.atproto.repo.describeRepo", params={"repo": rook.handle})
    assert described.status == 200
    body = described.json()
    assert body["did"] == rook.did and body["collections"] == ["app.bsky.feed.post"]
    assert isinstance(body["handle"], str) and body["handleIsCorrect"] is True
    assert body["didDoc"]["id"] == rook.did

    blocks = await client.get("/xrpc/com.atproto.sync.getBlocks", params={"did": rook.did, "cids": body["cid"]})
    assert blocks.status == 200 and blocks.headers["content-type"] == "application/vnd.ipld.car"
    roots, got = read_car(blocks.body)
    assert roots == [] and [str(cid) for cid in got] == [body["cid"]]
    missing = "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"
    blocks = await client.get("/xrpc/com.atproto.sync.getBlocks", params={"did": rook.did, "cids": missing})
    assert blocks.status == 400 and missing in blocks.json()["message"]

    latest = await client.get("/xrpc/com.atproto.sync.getLatestCommit", params={"did": rook.did})
    assert latest.status == 200
    assert isinstance(latest.json()["cid"], str) and isinstance(latest.json()["rev"], str)

    status = await client.get("/xrpc/com.atproto.sync.getRepoStatus", params={"did": rook.did})
    assert status.status == 200
    assert {k: status.json()[k] for k in ("did", "active", "status")} == {"did": rook.did, "active": True, "status": "active"}

    exported = await client.get("/xrpc/com.atproto.sync.getRepo", params={"did": rook.did})
    assert exported.status == 200
    assert exported.headers["content-type"] == "application/vnd.ipld.car"
    assert exported.body


async def test_custom_records_with_blob_links(client, enroll):
    rook = await enroll()
    upload = "/xrpc/com.atproto.repo.uploadBlob"
    uploaded = await client.post(upload, body=b"diff --git a/file b/file\n", headers=dict(
        rook.agent.auth_headers("POST", upload), **{"content-type": "application/gzip"}))
    assert uploaded.status == 200
    patch_blob = uploaded.json()["blob"]
    created = await rook.create("sh.tangled.repo.pull", {
        "$type": "sh.tangled.repo.pull",
        "title": "Route pull",
        "description": "Custom collection regression",
        "source": {"repo": f"at://{rook.did}/sh.tangled.repo/source", "branch": "feature"},
        "target": {"repo": f"at://{rook.did}/sh.tangled.repo/target", "branch": "main"},
        "rounds": [{"createdAt": "2026-01-01T00:00:00Z", "patchBlob": patch_blob}],
        "createdAt": "2026-01-01T00:00:00Z",
    }, "pull-rkey")
    assert created.status == 200, created.text

    got = await client.get("/xrpc/com.atproto.repo.getRecord", params={"repo": rook.handle, "collection": "sh.tangled.repo.pull", "rkey": "pull-rkey"})
    assert got.json()["value"]["rounds"][0]["patchBlob"]["ref"] == {"$link": patch_blob["ref"]["$link"]}
    listed = await client.get("/xrpc/com.atproto.repo.listRecords", params={"repo": rook.handle, "collection": "sh.tangled.repo.pull"})
    pull = next(record for record in listed.json()["records"] if record["uri"].endswith("/pull-rkey"))
    assert pull["value"]["rounds"][0]["patchBlob"]["ref"] == {"$link": patch_blob["ref"]["$link"]}


async def test_authenticated_repo_write_routes(client, enroll):
    rook = await enroll()
    base = {"repo": rook.did, "collection": "app.bsky.feed.post", "rkey": "write-rkey"}
    assert (await rook.post("/xrpc/com.atproto.repo.createRecord", dict(base, record={"text": "created"}))).status == 200
    assert (await rook.post("/xrpc/com.atproto.repo.putRecord", dict(base, record={"text": "updated"}))).status == 200
    applied = await rook.post("/xrpc/com.atproto.repo.applyWrites", {"repo": rook.did, "writes": [{
        "$type": "com.atproto.repo.applyWrites#update", "collection": "app.bsky.feed.post", "rkey": "write-rkey",
        "value": {"text": "batch-updated"},
    }]})
    assert applied.status == 200
    result = applied.json()["results"][0]
    assert result["$type"] == "com.atproto.repo.applyWrites#updateResult"
    assert result["uri"] == f"at://{rook.did}/app.bsky.feed.post/write-rkey"
    assert (await rook.post("/xrpc/com.atproto.repo.deleteRecord", base)).status == 200
    got = await client.get("/xrpc/com.atproto.repo.getRecord", params=base)
    assert got.status == 400 and got.json()["error"] == "RecordNotFound"


async def test_apply_writes_create_then_delete_in_one_batch(client, enroll):
    """The cirrus checker's atomic probe: a create and a delete of the same record."""
    rook = await enroll()
    write = {"collection": "app.bsky.feed.post", "rkey": "ephemeral"}
    applied = await rook.post("/xrpc/com.atproto.repo.applyWrites", {"repo": rook.did, "writes": [
        dict(write, **{"$type": "com.atproto.repo.applyWrites#create", "value": {"text": "brief"}}),
        dict(write, **{"$type": "com.atproto.repo.applyWrites#delete"}),
    ]})
    assert applied.status == 200, applied.text
    got = await client.get("/xrpc/com.atproto.repo.getRecord", params=dict(write, repo=rook.did))
    assert got.json()["error"] == "RecordNotFound"


async def test_account_management_reads(client, env, enroll):
    rook = await enroll()
    await rook.create("app.bsky.feed.post", {"text": "one"}, "one")
    status = await rook.get("/xrpc/com.atproto.server.checkAccountStatus")
    assert status.status == 200, status.text
    body = status.json()
    assert body["activated"] is True and body["validDid"] is True
    assert body["indexedRecords"] == 1 and body["repoBlocks"] > 0 and body["repoRev"]

    creds = (await rook.get("/xrpc/com.atproto.identity.getRecommendedDidCredentials")).json()
    assert creds["alsoKnownAs"] == [f"at://{rook.handle}"]
    assert creds["services"]["atproto_pds"]["endpoint"] == "https://rookery.test"
    assert creds["verificationMethods"]["atproto"].startswith("did:key:z")
    # The #atproto_kem key for space repo MACs is published at account creation.
    published = env.plc.log[rook.did][-1]["operation"]["verificationMethods"]
    assert creds["verificationMethods"]["atproto_kem"] == published["atproto_kem"]
    assert published["atproto_kem"].startswith("did:key:zDna")
    assert len(creds["rotationKeys"]) == 1

    assert (await rook.get("/xrpc/com.atproto.server.listAppPasswords")).json() == {"passwords": []}
    assert (await rook.get("/xrpc/com.atproto.server.getAccountInviteCodes")).json() == {"codes": []}
    assert (await client.get("/xrpc/com.atproto.server.checkAccountStatus")).status == 401
