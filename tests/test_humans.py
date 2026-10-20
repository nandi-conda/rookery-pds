# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

import base64
import json
from urllib.parse import urlencode

import pytest

from fakes import Client, Env
from human import sign_up
from roost import directory
from roost.net import HttpResponse


async def signup(client, name="alice", password="correct horse", **extra):
    return await sign_up(client, name, password, **extra)


async def test_create_account_session_and_repo_write(client, env):
    response = await signup(client, email="Alice@Example.com")
    assert response.status == 200, response.body
    account = response.json()
    assert account["handle"] == "alice.rookery.test" and account["did"].startswith("did:plc:")
    auth = {"authorization": f"Bearer {account['accessJwt']}"}

    session = (await client.get("/xrpc/com.atproto.server.getSession", headers=auth)).json()
    assert session["did"] == account["did"]

    write = await client.post("/xrpc/com.atproto.repo.createRecord", headers=auth, json_body={
        "repo": account["did"], "collection": "app.bsky.feed.post",
        "record": {"$type": "app.bsky.feed.post", "text": "hello", "createdAt": "2026-10-20T00:00:00Z"},
    })
    assert write.status == 200, write.body

    for identifier in ("alice.rookery.test", "alice@example.com", account["did"]):
        login = await client.post("/xrpc/com.atproto.server.createSession",
                                  json_body={"identifier": identifier, "password": "correct horse"})
        assert login.status == 200, (identifier, login.body)
    bad = await client.post("/xrpc/com.atproto.server.createSession",
                            json_body={"identifier": "alice.rookery.test", "password": "nope nope"})
    assert bad.status == 401

    refreshed = await client.post("/xrpc/com.atproto.server.refreshSession",
                                  headers={"authorization": f"Bearer {account['refreshJwt']}"})
    assert refreshed.status == 200
    # The old refresh token is spent, and so is the old access token.
    again = await client.post("/xrpc/com.atproto.server.refreshSession",
                              headers={"authorization": f"Bearer {account['refreshJwt']}"})
    assert again.status == 401
    stale = await client.get("/xrpc/com.atproto.server.getSession", headers=auth)
    assert stale.status == 401
    fresh = {"authorization": f"Bearer {refreshed.json()['accessJwt']}"}
    assert (await client.get("/xrpc/com.atproto.server.getSession", headers=fresh)).status == 200


async def test_create_account_validation(client, env):
    assert (await signup(client, password="short")).json()["error"] == "InvalidPassword"
    assert (await signup(client)).status == 200
    assert (await signup(client)).status == 409  # handle taken
    taken = await signup(client, name="bob", email="x@y.zz")
    assert taken.status == 200
    assert (await signup(client, name="carol", email="x@y.zz")).json()["error"] == "EmailTaken"


@pytest.fixture
def commons_client():
    return Client(Env(ROOKERY_VARIANT="commons"))


async def test_commons_requires_invite(commons_client):
    client, env = commons_client, commons_client.env
    assert (await signup(client)).json()["error"] == "InvalidInviteCode"
    await directory.init_directory(env.db)
    invite = await directory.mint_org_invite(env.db)
    token = invite["token"] if isinstance(invite, dict) else invite
    response = await signup(client, inviteCode=token)
    assert response.status == 200, response.body
    assert (await signup(client, name="bob", inviteCode=token)).json()["error"] == "InvalidInviteCode"


async def test_join_page(client, env):
    page = await client.get("/join")
    assert page.status == 200 and b"Create account" in page.body
    assert page.headers["x-frame-options"] == "DENY"
    form = urlencode({"handle": "dana", "password": "long enough pw", "tos": "1"})
    done = await client.post("/join", headers={"content-type": "application/x-www-form-urlencoded"},
                             body=form)
    assert done.status == 200 and b"Welcome, @dana.rookery.test" in done.body
    dup = await client.post("/join", headers={"content-type": "application/x-www-form-urlencoded"},
                            body=form)
    assert dup.status == 409 and b"already taken" in dup.body


async def test_preferences_and_appview_proxy(client, env):
    account = (await signup(client)).json()
    auth = {"authorization": f"Bearer {account['accessJwt']}"}
    prefs = [{"$type": "app.bsky.actor.defs#adultContentPref", "enabled": False}]
    put = await client.post("/xrpc/app.bsky.actor.putPreferences", headers=auth,
                            json_body={"preferences": prefs})
    assert put.status == 200
    got = (await client.get("/xrpc/app.bsky.actor.getPreferences", headers=auth)).json()
    assert got["preferences"] == prefs

    seen = {}

    async def appview(method, url, headers, body):
        seen.update(url=url, headers=headers)
        return HttpResponse(200, b'{"feed":[]}', {"content-type": "application/json"})
    env.http.routes["https://api.bsky.app/"] = appview
    timeline = await client.get("/xrpc/app.bsky.feed.getTimeline?limit=5", headers=auth)
    assert timeline.status == 200 and timeline.json() == {"feed": []}
    assert seen["url"] == "https://api.bsky.app/xrpc/app.bsky.feed.getTimeline?limit=5"
    token = seen["headers"]["authorization"].removeprefix("Bearer ")
    payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    assert payload["iss"] == account["did"] and payload["aud"] == "did:web:api.bsky.app"
    assert payload["lxm"] == "app.bsky.feed.getTimeline"
    unknown = await client.get("/xrpc/com.example.nothing", headers=auth)
    assert unknown.status == 501
