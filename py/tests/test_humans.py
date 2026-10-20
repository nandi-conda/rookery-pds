# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

import asyncio
import json
from urllib.parse import urlencode

from fakes import FakeEnv, body
from rookery import directory


def run(coro):
    return asyncio.run(coro)


async def signup(env, name="alice", password="correct horse", **extra):
    response = await env.request("POST", "/xrpc/com.atproto.server.createAccount",
                                 json_body={"handle": f"{name}.pds.test", "password": password, **extra})
    return response


def test_create_account_session_and_repo_write():
    async def go():
        env = FakeEnv()
        response = await signup(env, email="Alice@Example.com")
        assert response.status == 200, response.body
        account = body(response)
        assert account["handle"] == "alice.pds.test" and account["did"].startswith("did:plc:")
        auth = {"authorization": f"Bearer {account['accessJwt']}"}

        session = body(await env.request("GET", "/xrpc/com.atproto.server.getSession", headers=auth))
        assert session["did"] == account["did"]

        write = await env.request("POST", "/xrpc/com.atproto.repo.createRecord", headers=auth, json_body={
            "repo": account["did"], "collection": "app.bsky.feed.post",
            "record": {"$type": "app.bsky.feed.post", "text": "hello", "createdAt": "2026-10-20T00:00:00Z"},
        })
        assert write.status == 200, write.body

        for identifier in ("alice.pds.test", "alice@example.com", account["did"]):
            login = await env.request("POST", "/xrpc/com.atproto.server.createSession",
                                      json_body={"identifier": identifier, "password": "correct horse"})
            assert login.status == 200, (identifier, login.body)
        bad = await env.request("POST", "/xrpc/com.atproto.server.createSession",
                                json_body={"identifier": "alice.pds.test", "password": "nope nope"})
        assert bad.status == 401

        refreshed = await env.request("POST", "/xrpc/com.atproto.server.refreshSession",
                                      headers={"authorization": f"Bearer {account['refreshJwt']}"})
        assert refreshed.status == 200
        # The old refresh token is spent, and so is the old access token.
        again = await env.request("POST", "/xrpc/com.atproto.server.refreshSession",
                                  headers={"authorization": f"Bearer {account['refreshJwt']}"})
        assert again.status == 401
        stale = await env.request("GET", "/xrpc/com.atproto.server.getSession", headers=auth)
        assert stale.status == 401
        fresh = {"authorization": f"Bearer {body(refreshed)['accessJwt']}"}
        assert (await env.request("GET", "/xrpc/com.atproto.server.getSession", headers=fresh)).status == 200
    run(go())


def test_create_account_validation():
    async def go():
        env = FakeEnv()
        assert body(await signup(env, password="short"))["error"] == "InvalidPassword"
        assert (await signup(env)).status == 200
        assert (await signup(env)).status == 409  # handle taken
        taken = await signup(env, name="bob", email="x@y.zz")
        assert taken.status == 200
        assert body(await signup(env, name="carol", email="x@y.zz"))["error"] == "EmailTaken"
    run(go())


def test_commons_requires_invite():
    async def go():
        env = FakeEnv(variant="commons")
        assert body(await signup(env))["error"] == "InvalidInviteCode"
        await directory.init_directory(env.db)
        invite = await directory.mint_org_invite(env.db)
        token = invite["token"] if isinstance(invite, dict) else invite
        response = await signup(env, inviteCode=token)
        assert response.status == 200, response.body
        assert body(await signup(env, name="bob", inviteCode=token))["error"] == "InvalidInviteCode"
    run(go())


def test_join_page():
    async def go():
        env = FakeEnv()
        page = await env.request("GET", "/join")
        assert page.status == 200 and b"Create account" in page.body
        assert page.header("X-Frame-Options") == "DENY"
        form = urlencode({"handle": "dana", "password": "long enough pw", "tos": "1"})
        done = await env.request("POST", "/join", headers={"content-type": "application/x-www-form-urlencoded"},
                                 body=form)
        assert done.status == 200 and b"Welcome, @dana.pds.test" in done.body
        dup = await env.request("POST", "/join", headers={"content-type": "application/x-www-form-urlencoded"},
                                body=form)
        assert dup.status == 409 and b"already taken" in dup.body
    run(go())


def test_preferences_and_appview_proxy():
    async def go():
        env = FakeEnv()
        account = body(await signup(env))
        auth = {"authorization": f"Bearer {account['accessJwt']}"}
        prefs = [{"$type": "app.bsky.actor.defs#adultContentPref", "enabled": False}]
        put = await env.request("POST", "/xrpc/app.bsky.actor.putPreferences", headers=auth,
                                json_body={"preferences": prefs})
        assert put.status == 200
        got = body(await env.request("GET", "/xrpc/app.bsky.actor.getPreferences", headers=auth))
        assert got["preferences"] == prefs

        seen = {}

        async def appview(url, method, headers, body):
            from rookery.net import HttpResponse
            seen.update(url=url, headers=headers)
            return HttpResponse(200, b'{"feed":[]}', {"content-type": "application/json"})
        env.http.routes["https://api.bsky.app/"] = appview
        timeline = await env.request("GET", "/xrpc/app.bsky.feed.getTimeline?limit=5", headers=auth)
        assert timeline.status == 200 and body(timeline) == {"feed": []}
        assert seen["url"] == "https://api.bsky.app/xrpc/app.bsky.feed.getTimeline?limit=5"
        token = seen["headers"]["authorization"].removeprefix("Bearer ")
        payload = json.loads(__import__("base64").urlsafe_b64decode(token.split(".")[1] + "=="))
        assert payload["iss"] == account["did"] and payload["aud"] == "did:web:api.bsky.app"
        assert payload["lxm"] == "app.bsky.feed.getTimeline"
        unknown = await env.request("GET", "/xrpc/com.example.nothing", headers=auth)
        assert unknown.status == 501
    run(go())
