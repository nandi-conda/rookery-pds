# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Roost's own sign-in: /signin, /account and /signout with a browser session cookie."""

from human import PASSWORD, human

SAME_ORIGIN = {"origin": "https://rookery.test"}


def cookie_of(response) -> str:
    value = response.headers["set-cookie"]
    assert "HttpOnly" in value and "Secure" in value and "SameSite=Lax" in value
    return value.split(";")[0]


async def sign_in(client, identifier, password=PASSWORD):
    return await client.post("/signin", headers=SAME_ORIGIN, form={"identifier": identifier, "password": password})


async def test_sign_in_shows_account_and_sign_out(client):
    dana = await human(client, "dana")
    assert (await client.get("/account")).headers["location"] == "/signin"
    page = await client.get("/signin")
    assert page.status == 200 and b'action="/signin"' in page.body

    bad = await sign_in(client, "dana.rookery.test", "wrong password")
    assert bad.status == 401 and b"Invalid identifier or password" in bad.body and b'value="dana.rookery.test"' in bad.body

    ok = await sign_in(client, "@Dana.rookery.test")
    assert ok.status == 303 and ok.headers["location"] == "/account"
    cookie = {"cookie": cookie_of(ok)}
    account = await client.get("/account", headers=cookie)
    assert account.status == 200 and account.headers["cache-control"] == "no-store"
    assert b"@dana.rookery.test" in account.body and dana["did"].encode() in account.body
    assert (await client.get("/signin", headers=cookie)).headers["location"] == "/account"

    out = await client.post("/signout", headers={**cookie, **SAME_ORIGIN})
    assert out.status == 303 and "Max-Age=0" in out.headers["set-cookie"]
    assert (await client.get("/account", headers=cookie)).headers["location"] == "/signin"


async def test_posts_need_this_origin(client):
    await human(client, "erin")
    form = {"identifier": "erin.rookery.test", "password": PASSWORD}
    assert (await client.post("/signin", headers={"origin": "https://evil.example"}, form=form)).status == 403
    assert (await client.post("/signin", form=form)).status == 403
    same_site = await client.post("/signin", headers={"sec-fetch-site": "same-origin"}, form=form)
    assert same_site.status == 303
    cookie = {"cookie": cookie_of(same_site)}
    hostile = await client.post("/account", headers={**cookie, "origin": "https://evil.example"},
                                form={"action": "everywhere"})
    assert hostile.status == 403


async def test_change_password_signs_out_other_sessions(client):
    fran = await human(client, "fran")
    cookie = {"cookie": cookie_of(await sign_in(client, "fran.rookery.test")), **SAME_ORIGIN}
    other = {"cookie": cookie_of(await sign_in(client, "fran.rookery.test"))}

    wrong = await client.post("/account", headers=cookie,
                              form={"action": "password", "current": "nope nope", "password": "a new password"})
    assert wrong.status == 401
    short = await client.post("/account", headers=cookie,
                              form={"action": "password", "current": PASSWORD, "password": "short"})
    assert short.status == 400 and b"at least 8" in short.body

    done = await client.post("/account", headers=cookie,
                             form={"action": "password", "current": PASSWORD, "password": "a new password"})
    assert done.status == 303 and done.headers["location"] == "/account?done=password"
    assert b"Password changed" in (await client.get("/account?done=password", headers=cookie)).body
    assert (await client.get("/account", headers=other)).headers["location"] == "/signin"
    stale = await client.get("/xrpc/com.atproto.server.getSession", headers=fran["auth"])
    assert stale.status == 401
    assert (await sign_in(client, "fran.rookery.test")).status == 401
    assert (await sign_in(client, "fran", "a new password")).status == 303


async def test_sign_out_everywhere_keeps_this_browser(client):
    gil = await human(client, "gil")
    cookie = {"cookie": cookie_of(await sign_in(client, "gil.rookery.test")), **SAME_ORIGIN}
    done = await client.post("/account", headers=cookie, form={"action": "everywhere"})
    assert done.status == 303
    assert (await client.get("/xrpc/com.atproto.server.getSession", headers=gil["auth"])).status == 401
    assert (await client.get("/account", headers=cookie)).status == 200


async def test_change_handle(client):
    await human(client, "hana")
    await human(client, "taken")
    cookie = {"cookie": cookie_of(await sign_in(client, "hana.rookery.test")), **SAME_ORIGIN}
    clash = await client.post("/account", headers=cookie, form={"action": "handle", "handle": "taken"})
    assert clash.status == 409 and b"already taken" in clash.body
    done = await client.post("/account", headers=cookie, form={"action": "handle", "handle": "Hana2"})
    assert done.status == 303
    assert b"@hana2.rookery.test" in (await client.get("/account", headers=cookie)).body
    resolved = await client.get("/xrpc/com.atproto.identity.resolveHandle?handle=hana2.rookery.test")
    assert resolved.status == 200


async def test_entry_points_link_sign_in(client):
    assert b'href="/signin"' in (await client.get("/", headers={"accept": "text/html"})).body
    assert b'href="/signin"' in (await client.get("/join")).body
