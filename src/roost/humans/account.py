# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Roost's own sign-in for people: /signin, /signout and the /account page, where
a password account sees its identity, changes its handle or password, and signs
out of every app. The browser holds an opaque, hashed-at-rest session cookie;
every POST also has to come from this origin."""

from ..app import AuthFailure, _repoint_identity, check_handle_name, request_host, router
from ..errors import XrpcError
from ..oauth import store as oauth_store
from ..web import Response, redirect
from . import store
from .pages import render_account_page, render_signin_page
from .routes import check_login, failure_message, page

COOKIE = "__Host-roost_session"


def session_token(request) -> str | None:
    for part in (request.header("cookie") or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE and value:
            return value
    return None


async def signed_in(request, env) -> dict | None:
    token = session_token(request)
    return await store.resolve_web_session(env.db, token) if token else None


def same_origin(request, env) -> bool:
    """Forms post only from this host (the cookie is SameSite=Lax too)."""
    sent = request.header("origin")
    if sent:
        return sent == f"https://{request_host(request, env)}"
    return request.header("sec-fetch-site") == "same-origin"


def private(response: Response) -> Response:
    response.set_header("Cache-Control", "no-store")
    return response


def go(location: str, cookie: str | None = None) -> Response:
    response = private(redirect(location, 303))
    if cookie is not None:
        response.set_header("Set-Cookie", cookie)
    return response


def session_cookie(token: str) -> str:
    return f"{COOKIE}={token}; Path=/; Max-Age={store.WEB_SESSION_TTL_S}; HttpOnly; Secure; SameSite=Lax"


CLEAR_COOKIE = f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"


async def sign_out_elsewhere(env, did: str, token: str) -> None:
    await store.revoke_all_sessions(env.db, did, keep_web_token=token)
    await oauth_store.init_oauth(env.db)
    await oauth_store.delete_sessions_by_did(env.db, did)


def forbidden() -> Response:
    return page("<p>This form has to be sent from this site. Go back and try again.</p>", 403)


@router.get("/signin")
async def signin_page(request, env):
    if await signed_in(request, env):
        return go("/account")
    return private(page(render_signin_page(env)))


@router.post("/signin")
async def signin_submit(request, env):
    if not same_origin(request, env):
        return forbidden()
    form = await request.form()
    identifier = form.get("identifier") or ""
    try:
        login = await check_login(env, identifier, form.get("password") or "")
    except XrpcError as exc:
        return private(page(render_signin_page(env, identifier, exc.message), exc.status))
    return go("/account", session_cookie(await store.create_web_session(env.db, login["did"])))


@router.post("/signout")
async def signout(request, env):
    if not same_origin(request, env):
        return forbidden()
    token = session_token(request)
    if token:
        await store.delete_web_session(env.db, token)
    return go("/signin", CLEAR_COOKIE)


@router.get("/account")
async def account_page(request, env):
    account = await signed_in(request, env)
    if not account:
        return go("/signin")
    notice = {"password": "Password changed. Other apps and browsers were signed out.",
              "handle": "Handle changed.", "everywhere": "Signed out of every other app and browser."}
    return private(page(render_account_page(env, account, notice.get(request.query("done") or ""))))


@router.post("/account")
async def account_submit(request, env):
    if not same_origin(request, env):
        return forbidden()
    token = session_token(request)
    account = await store.resolve_web_session(env.db, token) if token else None
    if not account:
        return go("/signin")
    form = await request.form()
    action = form.get("action")
    try:
        if action == "password":
            login = await check_login(env, account["did"], form.get("current") or "")
            problem = store.password_problem(form.get("password"))
            if problem:
                raise XrpcError("InvalidPassword", problem)
            await store.change_password(env.db, login["did"], form["password"])
            await sign_out_elsewhere(env, account["did"], token)
        elif action == "handle":
            handle = await check_handle_name(env, (form.get("handle") or "").strip().lower(), account["did"])
            if handle != account["handle"]:
                await _repoint_identity(env, account["did"], account["do_id"], handle)
        elif action == "everywhere":
            await sign_out_elsewhere(env, account["did"], token)
        else:
            raise XrpcError("InvalidRequest", "Unknown action")
    except (XrpcError, AuthFailure) as exc:
        _, message, status = failure_message(exc)
        return private(page(render_account_page(env, account, problem=message), status))
    return go(f"/account?done={action}")
